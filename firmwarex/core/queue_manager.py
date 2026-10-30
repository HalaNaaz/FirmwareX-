"""Job queue management and concurrency bounding engine for FirmwareX.

Enforces PRD §7.2 (SC-2.3):
- Bounded concurrency: strictly limits simultaneous running analysis workers.
- Queue capacity & backpressure: rejects job admission when capacity is saturated.
- Durable state machine: queued -> running -> completed / failed / cancelled.
- Idempotency & duplicate submission detection.
- Worker fault isolation and error recovery without leaking execution slots.
- Safe graceful shutdown and cancellation.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from firmwarex.config import JOB_TIMEOUT_SECONDS


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class QueueBackpressureError(Exception):
    """Raised when queue capacity is saturated to protect system responsiveness."""
    pass


class JobCancelledError(Exception):
    """Raised when a running or queued job has been cancelled by an analyst."""
    pass


@dataclass
class JobState:
    job_id: str
    firmware_id: str
    sha256: str = ""
    status: JobStatus = JobStatus.QUEUED
    stage: str = "queued"
    progress: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    cancellation_requested: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, JobStatus) else str(self.status)
        return d


class JobQueueManager:
    """Coordinates worker concurrency, queue depth, backpressure, and job lifecycles."""

    def __init__(
        self,
        max_concurrency: int = 2,
        max_queue_size: int = 10,
        job_timeout_seconds: int = JOB_TIMEOUT_SECONDS,
        storage: Any = None,
    ):
        self.max_concurrency = max(1, max_concurrency)
        self.max_queue_size = max(self.max_concurrency, max_queue_size)
        self.job_timeout_seconds = job_timeout_seconds
        self.storage = storage

        self._lock = threading.Lock()
        self._async_sem: asyncio.Semaphore | None = None
        self._jobs: dict[str, JobState] = {}
        self._sha256_to_job: dict[str, str] = {}
        self._is_shutting_down: bool = False

        # Counters for metrics
        self._total_submitted: int = 0
        self._total_completed: int = 0
        self._total_failed: int = 0
        self._total_cancelled: int = 0
        self._total_rejected_backpressure: int = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._async_sem is None:
            self._async_sem = asyncio.Semaphore(self.max_concurrency)
        return self._async_sem

    def can_accept_job(self) -> bool:
        """Check whether the queue can accept an incoming job without breaching backpressure limit."""
        with self._lock:
            if self._is_shutting_down:
                return False
            active_count = sum(
                1 for j in self._jobs.values()
                if j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
            )
            return active_count < self.max_queue_size

    def get_active_job_by_sha256(self, sha256_hash: str) -> dict[str, Any] | None:
        """Find an in-flight (queued or running) job with the exact same firmware digest."""
        if not sha256_hash:
            return None
        with self._lock:
            job_id = self._sha256_to_job.get(sha256_hash)
            if job_id and job_id in self._jobs:
                job = self._jobs[job_id]
                if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                    return job.to_dict()
        return None

    def submit_job(self, job_id: str, firmware_id: str, sha256: str = "") -> JobState:
        """Admit a new job into the queue, enforcing backpressure limits."""
        with self._lock:
            if self._is_shutting_down:
                raise QueueBackpressureError("Service is shutting down. No new jobs accepted.")

            active_count = sum(
                1 for j in self._jobs.values()
                if j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
            )
            if active_count >= self.max_queue_size:
                self._total_rejected_backpressure += 1
                raise QueueBackpressureError(
                    f"Queue capacity saturated ({active_count}/{self.max_queue_size}). "
                    "Backpressure active to prevent system resource exhaustion."
                )

            # Idempotency check: if already active for exact sha256, return existing
            if sha256 and sha256 in self._sha256_to_job:
                existing_id = self._sha256_to_job[sha256]
                existing = self._jobs.get(existing_id)
                if existing and existing.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                    return existing

            state = JobState(
                job_id=job_id,
                firmware_id=firmware_id,
                sha256=sha256,
                status=JobStatus.QUEUED,
                stage="queued",
                progress=0,
            )
            self._jobs[job_id] = state
            if sha256:
                self._sha256_to_job[sha256] = job_id
            self._total_submitted += 1

            if self.storage:
                try:
                    self.storage.save_job(state.to_dict())
                except Exception:
                    pass

            return state

    @asynccontextmanager
    async def job_context(self, job_id: str, firmware_id: str, sha256: str = ""):
        """Context manager orchestrating bounded execution, lifecycle transitions, and cleanup."""
        # 1. Admit job into queue state or check existing
        with self._lock:
            if job_id in self._jobs:
                state = self._jobs[job_id]
                if state.cancellation_requested or state.status == JobStatus.CANCELLED:
                    raise JobCancelledError(f"Job {job_id} was cancelled before worker execution.")
            else:
                state = None
        if state is None:
            state = self.submit_job(job_id=job_id, firmware_id=firmware_id, sha256=sha256)

        sem = self._get_semaphore()
        acquired = False
        try:
            # 2. Wait for worker slot (bounded by concurrency limit)
            await sem.acquire()
            acquired = True

            # Check if cancelled while waiting in queue
            with self._lock:
                if state.cancellation_requested:
                    state.status = JobStatus.CANCELLED
                    state.stage = "cancelled"
                    state.completed_at = datetime.now(UTC).isoformat()
                    self._total_cancelled += 1
                    if self.storage:
                        self.storage.save_job(state.to_dict())
                    raise JobCancelledError(f"Job {job_id} was cancelled before worker execution.")

                state.status = JobStatus.RUNNING
                state.stage = "running"
                state.progress = 10
                state.started_at = datetime.now(UTC).isoformat()

            if self.storage:
                try:
                    self.storage.save_job(state.to_dict())
                except Exception:
                    pass

            # Yield control to the actual analysis pipeline
            yield state

            # 3. Mark completed on clean exit
            with self._lock:
                state.status = JobStatus.COMPLETED
                state.stage = "done"
                state.progress = 100
                state.completed_at = datetime.now(UTC).isoformat()
                self._total_completed += 1

            if self.storage:
                try:
                    self.storage.save_job(state.to_dict())
                except Exception:
                    pass

        except JobCancelledError:
            with self._lock:
                state.status = JobStatus.CANCELLED
                state.stage = "cancelled"
                state.completed_at = datetime.now(UTC).isoformat()
                self._total_cancelled += 1
            if self.storage:
                try:
                    self.storage.save_job(state.to_dict())
                except Exception:
                    pass
            raise

        except Exception as exc:
            # 4. Worker exception isolation and recovery
            with self._lock:
                state.status = JobStatus.FAILED
                state.stage = "failed"
                state.error_message = str(exc)
                state.completed_at = datetime.now(UTC).isoformat()
                self._total_failed += 1

            if self.storage:
                try:
                    self.storage.save_job(state.to_dict())
                except Exception:
                    pass
            raise

        finally:
            # Always release concurrency slot, even on crash or cancellation
            if acquired:
                sem.release()
            with self._lock:
                if sha256 and self._sha256_to_job.get(sha256) == job_id:
                    self._sha256_to_job.pop(sha256, None)

    def cancel_job(self, job_id: str) -> bool:
        """Request cancellation of an active or queued job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False

            if job.status == JobStatus.QUEUED:
                job.status = JobStatus.CANCELLED
                job.stage = "cancelled"
                job.cancellation_requested = True
                job.completed_at = datetime.now(UTC).isoformat()
                self._total_cancelled += 1
                if job.sha256:
                    self._sha256_to_job.pop(job.sha256, None)
                if self.storage:
                    try:
                        self.storage.save_job(job.to_dict())
                    except Exception:
                        pass
                return True

            elif job.status == JobStatus.RUNNING:
                job.cancellation_requested = True
                return True

            return False

    def is_cancelled(self, job_id: str) -> bool:
        """Check if job cancellation was requested."""
        with self._lock:
            job = self._jobs.get(job_id)
            return bool(job and job.cancellation_requested)

    def get_job_state(self, job_id: str) -> dict[str, Any] | None:
        """Retrieve live state of a tracked job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                return job.to_dict()
        if self.storage:
            return self.storage.get_job(job_id)
        return None

    def get_metrics(self) -> dict[str, Any]:
        """Produce comprehensive queue telemetry conforming to PRD §7.2."""
        with self._lock:
            queued = sum(1 for j in self._jobs.values() if j.status == JobStatus.QUEUED)
            running = sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)
            return {
                "max_concurrency": self.max_concurrency,
                "max_queue_size": self.max_queue_size,
                "active_workers": running,
                "queued_jobs": queued,
                "available_slots": max(0, self.max_concurrency - running),
                "queue_capacity_remaining": max(0, self.max_queue_size - (queued + running)),
                "total_submitted": self._total_submitted,
                "total_completed": self._total_completed,
                "total_failed": self._total_failed,
                "total_cancelled": self._total_cancelled,
                "total_rejected_backpressure": self._total_rejected_backpressure,
                "is_shutting_down": self._is_shutting_down,
                "is_healthy": not self._is_shutting_down and (queued + running) < self.max_queue_size,
            }

    async def shutdown(self, cancel_pending: bool = True):
        """Safely terminate queue processing and drain pending tasks."""
        with self._lock:
            self._is_shutting_down = True
            if cancel_pending:
                for job in self._jobs.values():
                    if job.status == JobStatus.QUEUED:
                        job.status = JobStatus.CANCELLED
                        job.stage = "cancelled_due_to_shutdown"
                        job.cancellation_requested = True
                        job.completed_at = datetime.now(UTC).isoformat()
                        self._total_cancelled += 1
                        if self.storage:
                            try:
                                self.storage.save_job(job.to_dict())
                            except Exception:
                                pass

    def reset(self):
        """Reset queue manager state (for testing isolation)."""
        with self._lock:
            self._jobs.clear()
            self._sha256_to_job.clear()
            self._is_shutting_down = False
            self._async_sem = None
            self._total_submitted = 0
            self._total_completed = 0
            self._total_failed = 0
            self._total_cancelled = 0
            self._total_rejected_backpressure = 0

