import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("backend"))

from app.db.session import AsyncSessionLocal, init_db
from app.analyzers.pipeline import run_phase3_pipeline
from app.models import Capture, AnalysisJob, EmailSession, InfrastructureIdentity, Finding
from sqlalchemy import select
from scripts.pcap_lab.generators import generate_scenario_b

async def main():
    await init_db()
    
    # 1. Generate scenario B PCAP (02_deprecated_tls.pcap)
    pcap_path = os.path.join("demo_pcaps", "02_deprecated_tls.pcap")
    pcap_bytes = generate_scenario_b()
    with open(pcap_path, "wb") as f:
        f.write(pcap_bytes)
    
    async with AsyncSessionLocal() as db:
        cap = Capture(
            filename="02_deprecated_tls.pcap",
            file_path=pcap_path,
            file_size_bytes=os.path.getsize(pcap_path),
            sha256_hash="test2hash",
            total_packets=5
        )
        db.add(cap)
        await db.flush()
        
        job = AnalysisJob(
            capture_id=cap.id,
            status="PENDING"
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        
        # Run forensic pipeline
        job_res = await run_phase3_pipeline(job.id, db)
        print("Pipeline Status:", job_res.status)
        print("Overall Risk Score:", job_res.overall_risk_score)
        print("Risk Band:", job_res.risk_band)
        print("Total Sessions:", job_res.total_sessions)
        print("Total Findings:", job_res.total_findings)
        
        # Query findings
        findings_stmt = select(Finding).where(Finding.job_id == job_res.id)
        findings = (await db.execute(findings_stmt)).scalars().all()
        print("Finding Rules:", [f.rule_id for f in findings])
        
        # Query infrastructure identity
        infra_stmt = select(InfrastructureIdentity).where(InfrastructureIdentity.last_evaluated_job_id == job_res.id)
        infras = (await db.execute(infra_stmt)).scalars().all()
        for i in infras:
            print("Infra IP:", i.ip_address)
            print("Infra Port:", i.port)
            print("Infra Protocol:", i.protocol)
            print("Infra Hostname:", i.hostname)
            print("Infra Key:", i.identity_key)
            print("Infra Profile JSON:", i.active_profile_json)

if __name__ == "__main__":
    asyncio.run(main())
