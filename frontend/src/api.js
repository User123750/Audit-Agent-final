const API_BASE = "http://192.168.3.20:8000";
export async function createAudit({ company, engineer, objective }) {
  const res = await fetch(`${API_BASE}/audits`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ company, engineer, objective }),
  });
  if (!res.ok) throw new Error("Impossible de créer l'audit");
  return res.json(); // { audit_id }
}

export async function getAuditStatus(auditId) {
  const res = await fetch(`${API_BASE}/audits/${auditId}`);
  if (!res.ok) throw new Error("Audit introuvable");
  return res.json(); // { done, report, error, pending_command }
}

export async function submitValidation(auditId, action, comments) {
  const res = await fetch(`${API_BASE}/audits/${auditId}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, comments }),
  });
  if (!res.ok) throw new Error("Échec de l'envoi de la validation");
  return res.json();
}