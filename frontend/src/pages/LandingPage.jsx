import React, { useEffect, useRef, useState } from 'react';
import Navbar from '../components/Navbar';

const LandingPage = ({ onStartAudit }) => {
  const howItWorksRef = useRef(null);
  const featuresRef = useRef(null);
  const reportRef = useRef(null);
  const [isVisible, setIsVisible] = useState({});

  useEffect(() => {
    if (window.location.hash === '#how-it-works' && howItWorksRef.current) {
      howItWorksRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);
   // Dans LandingPage.jsx, après les useState
useEffect(() => {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -50px 0px' }
  );

  const sections = document.querySelectorAll('.animate-on-scroll');
  sections.forEach((section) => observer.observe(section));

  return () => observer.disconnect();
}, []);
  // Intersection Observer pour les animations au scroll
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsVisible((prev) => ({ ...prev, [entry.target.id]: true }));
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -50px 0px' }
    );

    const sections = document.querySelectorAll('.animate-on-scroll');
    sections.forEach((section) => observer.observe(section));

    return () => observer.disconnect();
  }, []);

  const scrollToHowItWorks = () => {
    howItWorksRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="landing-page">
      {/* ===== NAVBAR ===== */}
      <Navbar onStartAudit={onStartAudit} />

      {/* ===== HERO ===== */}
      <section className="hero">
        <div className="hero-content animate-hero">
          <div className="hero-badge">
            <span className="live-dot"></span>
            <span className="typing-text">v0.1 — Projet de fin d'année</span>
          </div>
          <h1 className="hero-title">
            Audit réseau piloté par l'IA,<br />
            <span className="accent gradient-text">mais jamais sans vous</span>
          </h1>
          <p className="hero-subtitle typing-subtitle">
            OddNet découvre, analyse et propose des actions — mais chaque commande réseau
            reste soumise à votre validation avant exécution.
          </p>
          <div className="hero-actions">
            <button className="btn-primary btn-pulse" onClick={onStartAudit}>
              <span className="btn-content">
                <span className="btn-icon">🚀</span>
                Lancer un audit
              </span>
            </button>
            <button className="btn-secondary" onClick={scrollToHowItWorks}>
              <span className="btn-content">
                <span className="btn-icon">↓</span>
                Voir comment ça marche
              </span>
            </button>
          </div>
          <div className="hero-stats">
            <div className="stat-item">
              <span className="stat-number" data-count="100">0</span>
              <span className="stat-label">Hôtes scannables</span>
            </div>
            <div className="stat-item">
              <span className="stat-number" data-count="5">0</span>
              <span className="stat-label">Étapes pipeline</span>
            </div>
            <div className="stat-item">
              <span className="stat-number" data-count="100">0</span>
              <span className="stat-label">% contrôle humain</span>
            </div>
          </div>
        </div>
        <div className="hero-visual">
          <svg viewBox="0 0 400 300" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#d1d5db" strokeWidth="0.5" opacity="0.4">
                  <animate attributeName="opacity" values="0.4;0.6;0.4" dur="3s" repeatCount="indefinite"/>
                </path>
              </pattern>
              <radialGradient id="pulseGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#d97706" stopOpacity="0.3"/>
                <stop offset="100%" stopColor="#d97706" stopOpacity="0"/>
              </radialGradient>
              <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#d97706" stopOpacity="0.2"/>
                <stop offset="50%" stopColor="#d97706" stopOpacity="0.6"/>
                <stop offset="100%" stopColor="#d97706" stopOpacity="0.2"/>
              </linearGradient>
            </defs>

            <rect width="400" height="300" fill="url(#grid)" />

            {/* Lignes de connexion avec animation */}
            <line x1="80" y1="120" x2="200" y2="80" stroke="#94a3b8" strokeWidth="1.5" opacity="0.6">
              <animate attributeName="opacity" values="0.4;0.8;0.4" dur="2s" repeatCount="indefinite"/>
            </line>
            <line x1="200" y1="80" x2="320" y2="140" stroke="#94a3b8" strokeWidth="1.5" opacity="0.6">
              <animate attributeName="opacity" values="0.6;0.9;0.6" dur="2.5s" repeatCount="indefinite"/>
            </line>
            <line x1="80" y1="120" x2="160" y2="220" stroke="#94a3b8" strokeWidth="1.5" opacity="0.6">
              <animate attributeName="opacity" values="0.3;0.7;0.3" dur="3s" repeatCount="indefinite"/>
            </line>
            <line x1="160" y1="220" x2="320" y2="140" stroke="#94a3b8" strokeWidth="1.5" opacity="0.6">
              <animate attributeName="opacity" values="0.5;0.8;0.5" dur="2.2s" repeatCount="indefinite"/>
            </line>

            {/* Ligne de scan avec gradient */}
            <line x1="80" y1="120" x2="320" y2="140" stroke="url(#lineGrad)" strokeWidth="2">
              <animate attributeName="stroke-opacity" values="0.3;0.8;0.3" dur="1.5s" repeatCount="indefinite"/>
            </line>

            {/* Point central pulsé avancé */}
            <circle cx="200" cy="150" r="25" fill="url(#pulseGlow)">
              <animate attributeName="r" values="15;30;15" dur="2s" repeatCount="indefinite"/>
              <animate attributeName="opacity" values="0.3;0.05;0.3" dur="2s" repeatCount="indefinite"/>
            </circle>
            <circle cx="200" cy="150" r="8" fill="#d97706">
              <animate attributeName="r" values="6;10;6" dur="1.5s" repeatCount="indefinite"/>
            </circle>
            <circle cx="200" cy="150" r="3" fill="#ffffff">
              <animate attributeName="opacity" values="1;0.3;1" dur="1s" repeatCount="indefinite"/>
            </circle>

            {/* Nœuds réseau avec animations */}
            <g className="node">
              <circle cx="80" cy="120" r="6" fill="#d97706">
                <animate attributeName="r" values="5;8;5" dur="2s" repeatCount="indefinite"/>
              </circle>
              <circle cx="80" cy="120" r="10" fill="#d97706" opacity="0.2">
                <animate attributeName="r" values="8;14;8" dur="2s" repeatCount="indefinite"/>
                <animate attributeName="opacity" values="0.3;0.05;0.3" dur="2s" repeatCount="indefinite"/>
              </circle>
              <text x="80" y="105" fill="#475569" fontSize="10" fontFamily="JetBrains Mono" textAnchor="middle">
                10.0.0.1
                <animate attributeName="opacity" values="0.6;1;0.6" dur="3s" repeatCount="indefinite"/>
              </text>
            </g>

            <g className="node">
              <circle cx="320" cy="140" r="6" fill="#d97706">
                <animate attributeName="r" values="5;8;5" dur="2.5s" repeatCount="indefinite"/>
              </circle>
              <circle cx="320" cy="140" r="10" fill="#d97706" opacity="0.2">
                <animate attributeName="r" values="8;14;8" dur="2.5s" repeatCount="indefinite"/>
                <animate attributeName="opacity" values="0.3;0.05;0.3" dur="2.5s" repeatCount="indefinite"/>
              </circle>
              <text x="320" y="125" fill="#475569" fontSize="10" fontFamily="JetBrains Mono" textAnchor="middle">
                10.0.0.5
                <animate attributeName="opacity" values="0.6;1;0.6" dur="3.5s" repeatCount="indefinite"/>
              </text>
            </g>

            <g className="node">
              <circle cx="160" cy="220" r="6" fill="#d97706">
                <animate attributeName="r" values="5;8;5" dur="3s" repeatCount="indefinite"/>
              </circle>
              <circle cx="160" cy="220" r="10" fill="#d97706" opacity="0.2">
                <animate attributeName="r" values="8;14;8" dur="3s" repeatCount="indefinite"/>
                <animate attributeName="opacity" values="0.3;0.05;0.3" dur="3s" repeatCount="indefinite"/>
              </circle>
              <text x="160" y="205" fill="#475569" fontSize="10" fontFamily="JetBrains Mono" textAnchor="middle">
                10.0.0.12
                <animate attributeName="opacity" values="0.6;1;0.6" dur="4s" repeatCount="indefinite"/>
              </text>
            </g>

            {/* Particules de scan */}
            <circle r="3" fill="#d97706" opacity="0.9">
              <animateMotion dur="3s" repeatCount="indefinite" path="M80,120 L200,80 L320,140 L200,150 Z"/>
              <animate attributeName="r" values="2;5;2" dur="0.5s" repeatCount="indefinite"/>
            </circle>
            <circle r="2" fill="#fbbf24" opacity="0.6">
              <animateMotion dur="4s" repeatCount="indefinite" path="M160,220 L200,80 L80,120 L200,150 Z"/>
              <animate attributeName="opacity" values="0.3;0.8;0.3" dur="1s" repeatCount="indefinite"/>
            </circle>

            {/* Effet de vague radar */}
            <path d="M 200 150 L 250 100 A 70 70 0 0 1 270 150 Z" fill="none" stroke="#d97706" strokeWidth="1" opacity="0.3">
              <animateTransform attributeName="transform" type="rotate" from="0 200 150" to="360 200 150" dur="8s" repeatCount="indefinite"/>
            </path>
          </svg>
        </div>
      </section>

      {/* ===== LE PROBLÈME / LA PROMESSE ===== */}
      <section className="problem-promise">
        <div className="promise-grid">
          <div className="promise-card animate-on-scroll" id="promise-1">
            <div className="promise-icon">⏳</div>
            <h3>Les audits manuels sont lents</h3>
            <p>Scanner des centaines d'hôtes, analyser des milliers de ports, interpréter les résultats… un travail chronophage et sujet à l'erreur.</p>
          </div>
          <div className="promise-card highlight animate-on-scroll" id="promise-2">
            <div className="promise-icon">⚖️</div>
            <h3>Les outils autonomes sont risqués</h3>
            <p>Une commande Nmap mal placée, un SSH non supervisé, une collecte intrusive… l'automatisation aveugle peut dégrader un réseau.</p>
          </div>
          <div className="promise-card animate-on-scroll" id="promise-3">
            <div className="promise-icon">🎯</div>
            <h3>OddNet fait les deux : rapide ET supervisé</h3>
            <p>L'IA génère les commandes, vous validez chaque action. La vitesse de l'automatisation, la sécurité du contrôle humain.</p>
          </div>
        </div>
      </section>

      {/* ===== COMMENT ÇA MARCHE ===== */}
      <section className="how-it-works" ref={howItWorksRef} id="how-it-works">
        <h2 className="section-title animate-on-scroll" id="title-how">Comment ça marche</h2>
        <p className="section-subtitle animate-on-scroll" id="subtitle-how">
          Un pipeline en 5 étapes, de la découverte du réseau à la génération du rapport.
        </p>

        <div className="timeline">
          <div className="timeline-step animate-on-scroll" id="step-1">
            <div className="step-icon pulse-icon">1</div>
            <div className="step-content">
              <h4>Discovery</h4>
              <p>Scan du sous-réseau pour identifier les hôtes actifs et leurs adresses IP.</p>
              <code className="step-code">nmap -sn 192.168.1.0/24</code>
            </div>
          </div>
          <div className="timeline-step animate-on-scroll" id="step-2">
            <div className="step-icon pulse-icon">2</div>
            <div className="step-content">
              <h4>Enumeration</h4>
              <p>Scan détaillé par hôte : détection OS, services ouverts et versions.</p>
              <code className="step-code">nmap -O -sV -p- 192.168.1.1</code>
            </div>
          </div>
          <div className="timeline-step animate-on-scroll" id="step-3">
            <div className="step-icon pulse-icon">3</div>
            <div className="step-content">
              <h4>Access Strategy</h4>
              <p>Identification des hôtes accessibles en SSH et préparation des connexions.</p>
              <code className="step-code">ssh -o ConnectTimeout=5 user@192.168.1.1</code>
            </div>
          </div>
          <div className="timeline-step animate-on-scroll" id="step-4">
            <div className="step-icon pulse-icon">4</div>
            <div className="step-content">
              <h4>Identity Collection</h4>
              <p>Collecte sécurisée des informations système via SSH (users, processus, services).</p>
              <code className="step-code">ssh user@host "who -a; ps aux"</code>
            </div>
          </div>
          <div className="timeline-step animate-on-scroll" id="step-5">
            <div className="step-icon pulse-icon">5</div>
            <div className="step-content">
              <h4>Classification</h4>
              <p>Catégorisation automatique des actifs : Linux Endpoint, Single Server, Mac Endpoint, etc.</p>
              <code className="step-code">→ Linux Server (Ubuntu 22.04) — 4 ports ouverts</code>
            </div>
          </div>
        </div>

        {/* Encart HITL */}
        <div className="hitl-encart animate-on-scroll" id="hitl-encart">
          <div className="hitl-header">
            <span className="hitl-badge">⚡ Le point différenciant</span>
            <h3>Human-In-The-Loop : chaque commande est validée</h3>
          </div>
          <div className="hitl-preview">
            <div className="hitl-command-card">
              <div className="command-header">
                <span className="command-badge">nmap</span>
                <span className="command-host">10.0.0.1</span>
              </div>
              <code className="command-full typing-code">nmap -O -sV -p- 10.0.0.1</code>
              <div className="command-actions">
                <button className="cmd-approve cmd-hover">✔ Approuver</button>
                <button className="cmd-modify cmd-hover">✎ Modifier</button>
                <button className="cmd-reject cmd-hover">✕ Rejeter</button>
              </div>
              <p className="command-note">L'IA propose → vous décidez. Aucune commande n'est exécutée sans votre accord.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ===== FONCTIONNALITÉS ===== */}
      <section className="features" ref={featuresRef} id="features">
        <h2 className="section-title animate-on-scroll" id="title-features">Fonctionnalités</h2>
        <div className="features-grid">
          <div className="feature-card animate-on-scroll" id="feature-1">
            <div className="feature-icon float-icon">🔍</div>
            <h4>Détection OS & services</h4>
            <p>Fingerprinting Nmap avancé pour identifier OS, versions de services et bannières.</p>
          </div>
          <div className="feature-card animate-on-scroll" id="feature-2">
            <div className="feature-icon float-icon">🏷️</div>
            <h4>Classification automatique</h4>
            <p>Catégorisation des actifs : Linux Endpoint, Single Server, Mac Endpoint, etc.</p>
          </div>
          <div className="feature-card animate-on-scroll" id="feature-3">
            <div className="feature-icon float-icon">🔐</div>
            <h4>Collecte SSH sécurisée</h4>
            <p>Extraction d'informations système via SSH avec gestion des credentials dédiée.</p>
          </div>
          <div className="feature-card highlight-card animate-on-scroll" id="feature-4">
            <div className="feature-icon float-icon">🧑‍💻</div>
            <h4>Validation humaine</h4>
            <p>Chaque commande est soumise à approbation, modification ou rejet avant exécution.</p>
          </div>
          <div className="feature-card animate-on-scroll" id="feature-5">
            <div className="feature-icon float-icon">📊</div>
            <h4>Rapport structuré</h4>
            <p>Risques puis Recommandations par machine, avec hiérarchisation des priorités.</p>
          </div>
          <div className="feature-card animate-on-scroll" id="feature-6">
            <div className="feature-icon float-icon">📜</div>
            <h4>Historique complet</h4>
            <p>Traçabilité de chaque commande, décision prise et résultat obtenu.</p>
          </div>
        </div>
      </section>

      {/* ===== APERÇU DU RAPPORT ===== */}
      <section className="report-preview" ref={reportRef} id="report">
        <h2 className="section-title animate-on-scroll" id="title-report">Aperçu du rapport</h2>
        <p className="section-subtitle animate-on-scroll" id="subtitle-report">Un rapport clair, technique et exploitable — par machine.</p>
        <div className="report-card animate-on-scroll" id="report-card">
          <div className="report-header">
            <span className="report-host">🖥️ ubuntu-server.local</span>
            <span className="report-classification">Linux Server</span>
          </div>
          <div className="report-ip">
            <span>10.0.0.5</span>
            <span className="report-ports">22 (ssh) • 80 (http) • 443 (https)</span>
          </div>
          <div className="report-section">
            <h5>Risques</h5>
            <ul className="report-risks">
              <li className="risk-item">• Service SSH exposé sur port 22 — version OpenSSH 7.9p1 (CVE-2020-15778)</li>
              <li className="risk-item">• Serveur web sans TLS 1.3 détecté</li>
            </ul>
          </div>
          <div className="report-section">
            <h5>Recommandations</h5>
            <ul className="report-recommendations">
              <li className="rec-item">• Mettre à jour OpenSSH vers la version 8.4+ pour corriger CVE-2020-15778</li>
              <li className="rec-item">• Activer TLS 1.3 sur le service HTTP</li>
            </ul>
          </div>
        </div>
      </section>

      {/* ===== CTA FINAL ===== */}
      <section className="cta-final">
        <h2 className="animate-on-scroll" id="cta-title">Prêt à auditer votre réseau ?</h2>
        <p className="animate-on-scroll" id="cta-subtitle">Découvrez automatiquement vos actifs, analysez les risques, restez en contrôle.</p>
        <button className="btn-primary btn-pulse animate-on-scroll" id="cta-btn" onClick={onStartAudit}>
          <span className="btn-content">
            <span className="btn-icon">🚀</span>
            Lancer un audit
          </span>
        </button>
      </section>

      {/* ===== FOOTER ===== */}
      <footer className="landing-footer">
        <div className="footer-content">
          <span className="footer-brand">OddNet</span>
          <span className="footer-separator">•</span>
          <span>Oddnet</span>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;