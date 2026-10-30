"""Unit and integration tests for SC-2.3 Queue Concurrency and Backpressure Control.

Covers PRD §7.2 (SC-2.3) and Phase 1 Acceptance Criteria:
1. Job lifecycle state transitions: queued -> running -> completed, failed, and cancelled.
2. Concurrency limiting: strictly limits simultaneous running analysis workers to max_concurrency.
3. Queue capacity and backpressure: rejects job admission when capacity is saturated.
4. Worker exception handling: errors in workers are isolated and slots are safely reclaimed.
5. Idempotent duplicate submission handling.
6. Safe shutdown and resource exhaustion defense.
7. REST API queue endpoints: GET /api/v1/queue/status and POST /api/v1/jobs/{job_id}/cancel.
"""

import asyncio

import pytest
from starlette.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.core.queue_manager import (
    JobCancelledError,
    JobQueueManager,
    JobStatus,
    QueueBackpressureError,
)


@pytest.fixture
def queue_mgr():
    """Fresh isolated JobQueueManager instance."""
    mgr = JobQueueManager(max_concurrency=2, max_queue_size=4)
    yield mgr
    mgr.reset()


@pytest.mark.asyncio
async def test_job_lifecycle_queued_running_completed(queue_mgr):
    """Verify standard happy-path lifecycle transitions: queued -> running -> completed."""
    job_id = "job-life-1"
    fw_id = "fw-life-1"

    async with queue_mgr.job_context(job_id=job_id, firmware_id=fw_id, sha256="hash-1") as state:
        assert state.status == JobStatus.RUNNING
        assert state.stage == "running"
        assert state.progress == 10
        assert state.started_at is not None
        # Simulate worker processing
        await asyncio.sleep(0.01)

    # After context exit, job must be completed
    final_state = queue_mgr.get_job_state(job_id)
    assert final_state["status"] == JobStatus.COMPLETED
    assert final_state["stage"] == "done"
    assert final_state["progress"] == 100
    assert final_state["completed_at"] is not None

    metrics = queue_mgr.get_metrics()
    assert metrics["total_completed"] == 1
    assert metrics["active_workers"] == 0


@pytest.mark.asyncio
async def test_concurrency_limiting_under_simultaneous_jobs(queue_mgr):
    """Verify that at most max_concurrency workers run simultaneously."""
    max_active_observed = 0
    lock = asyncio.Lock()

    async def worker_task(job_id: str):
        nonlocal max_active_observed
        async with queue_mgr.job_context(job_id=job_id, firmware_id=f"fw-{job_id}"):
            async with lock:
                current_active = queue_mgr.get_metrics()["active_workers"]
                if current_active > max_active_observed:
                    max_active_observed = current_active
            await asyncio.sleep(0.05)

    # Launch 4 jobs with max_concurrency=2
    tasks = [asyncio.create_task(worker_task(f"job-conc-{i}")) for i in range(4)]
    await asyncio.gather(*tasks)

    # Concurrency must strictly never exceed 2
    assert max_active_observed <= 2
    metrics = queue_mgr.get_metrics()
    assert metrics["total_completed"] == 4
    assert metrics["active_workers"] == 0


@pytest.mark.asyncio
async def test_queue_capacity_and_backpressure_rejection(queue_mgr):
    """Verify that when queue capacity (max_queue_size=4) is reached, further jobs are rejected."""
    # Submit 4 jobs to saturate queue capacity
    for i in range(4):
        queue_mgr.submit_job(job_id=f"job-sat-{i}", firmware_id=f"fw-{i}")

    assert queue_mgr.can_accept_job() is False

    # 5th job must raise QueueBackpressureError
    with pytest.raises(QueueBackpressureError) as exc_info:
        queue_mgr.submit_job(job_id="job-overflow", firmware_id="fw-overflow")

    assert "Backpressure active" in str(exc_info.value)
    metrics = queue_mgr.get_metrics()
    assert metrics["total_rejected_backpressure"] == 1


@pytest.mark.asyncio
async def test_worker_exception_isolation_and_slot_recovery(queue_mgr):
    """Verify that a worker exception marks job failed and safely reclaims the concurrency slot."""
    job_id = "job-fault-1"

    with pytest.raises(RuntimeError) as exc_info:
        async with queue_mgr.job_context(job_id=job_id, firmware_id="fw-fault"):
            raise RuntimeError("Simulated unexpected crash during ELF disassembly.")

    assert "Simulated unexpected crash" in str(exc_info.value)

    state = queue_mgr.get_job_state(job_id)
    assert state["status"] == JobStatus.FAILED
    assert state["stage"] == "failed"
    assert "Simulated unexpected crash" in state["error_message"]

    # Crucial: concurrency slot must be restored to 0 active workers
    metrics = queue_mgr.get_metrics()
    assert metrics["active_workers"] == 0
    assert metrics["total_failed"] == 1
    assert metrics["available_slots"] == 2

    # Subsequent job must run cleanly without obstruction
    async with queue_mgr.job_context(job_id="job-recovery", firmware_id="fw-recovery"):
        pass
    assert queue_mgr.get_metrics()["total_completed"] == 1


@pytest.mark.asyncio
async def test_cancellation_of_queued_job(queue_mgr):
    """Verify that a queued job can be cancelled before worker execution starts."""
    job_id = "job-cancel-queue"
    queue_mgr.submit_job(job_id=job_id, firmware_id="fw-c1")

    assert queue_mgr.cancel_job(job_id) is True

    state = queue_mgr.get_job_state(job_id)
    assert state["status"] == JobStatus.CANCELLED
    assert state["stage"] == "cancelled"

    # Trying to execute cancelled job raises JobCancelledError immediately
    with pytest.raises(JobCancelledError):
        async with queue_mgr.job_context(job_id=job_id, firmware_id="fw-c1"):
            pytest.fail("Should not execute worker body of cancelled job")


@pytest.mark.asyncio
async def test_idempotent_duplicate_submission_detection(queue_mgr):
    """Verify that submitting duplicate jobs with identical firmware digest returns the active job."""
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    state1 = queue_mgr.submit_job(job_id="job-orig", firmware_id="fw-orig", sha256=sha)
    assert state1.job_id == "job-orig"

    active = queue_mgr.get_active_job_by_sha256(sha)
    assert active is not None
    assert active["job_id"] == "job-orig"

    # Re-submitting identical hash returns existing active job
    state2 = queue_mgr.submit_job(job_id="job-dup", firmware_id="fw-dup", sha256=sha)
    assert state2.job_id == "job-orig"


@pytest.mark.asyncio
async def test_safe_shutdown_cancels_pending_jobs(queue_mgr):
    """Verify graceful shutdown halts admission and cancels pending queued tasks."""
    queue_mgr.submit_job(job_id="job-pend-1", firmware_id="fw-1")
    queue_mgr.submit_job(job_id="job-pend-2", firmware_id="fw-2")

    await queue_mgr.shutdown(cancel_pending=True)

    metrics = queue_mgr.get_metrics()
    assert metrics["is_shutting_down"] is True
    assert metrics["is_healthy"] is False

    # Pending jobs marked cancelled
    assert queue_mgr.get_job_state("job-pend-1")["status"] == JobStatus.CANCELLED
    assert queue_mgr.get_job_state("job-pend-2")["status"] == JobStatus.CANCELLED

    # New submissions rejected
    with pytest.raises(QueueBackpressureError):
        queue_mgr.submit_job(job_id="job-late", firmware_id="fw-late")


def test_api_queue_status_and_cancel_endpoints():
    """Verify live FastAPI REST endpoints for queue status and job cancellation."""
    client = TestClient(app)

    # 1. GET /api/v1/queue/status
    resp = client.get("/api/v1/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "max_concurrency" in data
    assert "max_queue_size" in data
    assert "active_workers" in data
    assert "is_healthy" in data
    assert data["is_healthy"] is True

    # 2. GET /api/v1/jobs
    resp_jobs = client.get("/api/v1/jobs")
    assert resp_jobs.status_code == 200
    assert "jobs" in resp_jobs.json()
    assert isinstance(resp_jobs.json()["jobs"], list)

    # 3. POST /api/v1/jobs/{job_id}/cancel for nonexistent job -> 404
    resp_nonexistent = client.post("/api/v1/jobs/nonexistent-9999/cancel")
    assert resp_nonexistent.status_code == 404
