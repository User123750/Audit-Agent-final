from backend.models.audit import AuditInfo
from langgraph.workflow import Workflow

state = {
    "audit": AuditInfo(
        company="Test Company",
        engineer="Test Engineer",
        objective="Network Discovery"
    ),
    
    # 1. N-simuliw blli Network Agent deja dar khedmto bach n-zrbo
    "network_info": {
        "ip_address": "192.168.3.0",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.3.99"
    },
    
    "command_history": [],
    "current_command": None,
    "guardrail_status": None,
    "validation": None,
    "execution_output": None,
    "report": None,

    # 2. N-bdaw directement mn l'Enumeration w n-ne9zo Discovery
    "stage": "enumeration",
    
    # 3. N-3tiweh ghir les 2 IPs li 3ndna fihom l'accès f JSON!
    "discovered_hosts": ["192.168.3.10", "192.168.3.99"],
    
    # 4. N-gouloulih ydir ghir ping (-sn) w ydouz dghya dghya l Access Strategy
    "commands_per_host": ["-sn", "-sV"],
    
    "current_host_index": 0,
    "current_command_index": 0,
    "host_results": {},
    "partial_reports": {},
    "structured_hosts": {},
    "access_strategies": {},
    
    "batch_approved": None
}

print("\n========== STARTING ODDNET AUDIT TEST ==========\n")

result = Workflow.run(state)

print("\n========== AUDIT FINISHED ==========\n")
print("\n========== FINAL STATE ==========\n")
print(result)