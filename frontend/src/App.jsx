import { useEffect, useRef, useState } from "react";
import { createAudit, getAuditStatus, submitValidation } from "./api.js";
import LandingPage from "./pages/LandingPage.jsx";

const RISK_LABELS = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
  Critical: "risk-critical",
};

function NewAuditForm({ onCreated, onCancel }) {
  const [company, setCompany] = useState("");
  const [engineer, setEngineer] = useState("");
  const [objective, setObjective] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { audit_id } = await createAudit({ company, engineer, objective });
      onCreated(audit_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="card audit-form" onSubmit={handleSubmit}>
      <div className="form-header">
        <h2>Nouvel audit</h2>
        <button type="button" className="btn-close" onClick={onCancel}>✕</button>
      </div>
      <label>
        Entreprise
        <input value={company} onChange={(e) => setCompany(e.target.value)} required />
      </label>
      <label>
        Ingénieur
        <input value={engineer} onChange={(e) => setEngineer(e.target.value)} required />
      </label>
      <label>
        Objectif
        <input value={objective} onChange={(e) => setObjective(e.target.value)} required />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={loading}>
        {loading ? "Lancement..." : "Lancer l'audit"}
      </button>
    </form>
  );
}

function CommandCard({ command, onValidate }) {
  const [showModify, setShowModify] = useState(false);
  const [comments, setComments] = useState("");
  const riskClass = RISK_LABELS[command.risk_level] || "risk-medium";

  return (
    <div className="card command-card">
      <div className="card-header">
        <h2>Commande proposée — validation requise</h2>
        <span className={`badge ${riskClass}`}>{command.risk_level}</span>
      </div>

      <pre className="command-line">{command.command}</pre>

      <dl className="details">
        <dt>Objectif</dt>
        <dd>{command.objective}</dd>
        <dt>Description</dt>
        <dd>{command.description}</dd>
        <dt>Impact</dt>
        <dd>{command.impact}</dd>
        <dt>Durée estimée</dt>
        <dd>{command.estimated_duration}</dd>
        <dt>Justification</dt>
        <dd>{command.justification}</dd>
      </dl>

      {command.arguments?.length > 0 && (
        <>
          <h3>Arguments</h3>
          <ul className="arguments">
            {command.arguments.map((a, i) => (
              <li key={i}>
                <code>{a.argument}</code> — {a.explanation}
              </li>
            ))}
          </ul>
        </>
      )}

      {showModify && (
        <textarea
          className="modify-box"
          placeholder="Quelle modification demander à l'agent ?"
          value={comments}
          onChange={(e) => setComments(e.target.value)}
        />
      )}

      <div className="actions">
        <button className="approve" onClick={() => onValidate("Approve")}>
          ✔ Approuver
        </button>
        <button
          className="modify"
          onClick={() => {
            if (showModify) {
              onValidate("Modify", comments);
            } else {
              setShowModify(true);
            }
          }}
        >
          {showModify ? "✎ Envoyer la modification" : "✎ Modifier"}
        </button>
        <button className="reject" onClick={() => onValidate("Reject")}>
          ✕ Rejeter
        </button>
      </div>
    </div>
  );
}

function AuditTracker({ auditId, onBack }) {
  const [status, setStatus] = useState(null);
  const [validating, setValidating] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    async function poll() {
      try {
        const data = await getAuditStatus(auditId);
        setStatus(data);
      } catch {
        // audit pas encore prêt côté serveur — on réessaie au prochain tick
      }
    }
    poll();
    intervalRef.current = setInterval(poll, 2000);
    return () => clearInterval(intervalRef.current);
  }, [auditId]);

  async function handleValidate(action, comments) {
    setValidating(true);
    try {
      await submitValidation(auditId, action, comments);
    } finally {
      setValidating(false);
    }
  }

  if (!status) {
    return (
      <div className="audit-loading">
        <button className="btn-back" onClick={onBack}>← Retour</button>
        <p className="muted">Connexion à l'audit {auditId}...</p>
        <div className="spinner"></div>
      </div>
    );
  }

  if (status.error) {
    return (
      <div className="audit-error">
        <button className="btn-back" onClick={onBack}>← Retour</button>
        <p className="error">Erreur pendant l'audit : {status.error}</p>
      </div>
    );
  }

  if (status.done) {
    return (
      <div className="audit-done">
        <button className="btn-back" onClick={onBack}>← Retour</button>
        <div className="card">
          <h2>Rapport final</h2>
          <pre className="report">{status.report}</pre>
          <button className="btn-secondary" onClick={onBack}>
            Retour à l'accueil
          </button>
        </div>
      </div>
    );
  }

  if (status.pending_command) {
    return (
      <div className="audit-command">
        <button className="btn-back" onClick={onBack}>← Retour</button>
        <CommandCard
          command={status.pending_command}
          onValidate={validating ? () => {} : handleValidate}
        />
      </div>
    );
  }

  return (
    <div className="audit-waiting">
      <button className="btn-back" onClick={onBack}>← Retour</button>
      <p className="muted">Audit en cours — en attente de la prochaine commande...</p>
      <div className="spinner"></div>
    </div>
  );
}

export default function App() {
  const [currentPage, setCurrentPage] = useState("landing");
  const [auditId, setAuditId] = useState(null);

  const handleNewAudit = () => {
    setCurrentPage("new-audit");
  };

  const handleAuditCreated = (id) => {
    setAuditId(id);
    setCurrentPage("audit-tracker");
  };

  const handleBack = () => {
    setCurrentPage("landing");
    setAuditId(null);
  };

  const handleCancelNewAudit = () => {
    setCurrentPage("landing");
  };

  if (currentPage === "landing") {
    return <LandingPage onStartAudit={handleNewAudit} />;
  }

  if (currentPage === "new-audit") {
    return (
      <div className="app-page">
        <header className="app-header">
          <h1>OddNet</h1>
          <p className="subtitle">Validation humaine des commandes d'audit</p>
        </header>
        <div className="page-content">
          <NewAuditForm 
            onCreated={handleAuditCreated} 
            onCancel={handleCancelNewAudit}
          />
        </div>
      </div>
    );
  }

  if (currentPage === "audit-tracker") {
    return (
      <div className="app-page">
        <header className="app-header">
          <h1>OddNet</h1>
          <p className="subtitle">Audit en cours — {auditId}</p>
        </header>
        <div className="page-content">
          <AuditTracker auditId={auditId} onBack={handleBack} />
        </div>
      </div>
    );
  }

  return null;
}