import React, { useState } from 'react';

const Navbar = ({ onStartAudit, currentPage }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
    setIsMobileMenuOpen(false);
  };

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand">
          <span className="brand-logo">OddNet</span>
          <span className="brand-dot">•</span>
          <span className="brand-subtitle">Audit Network</span>
        </div>

        {/* Desktop Menu */}
        <ul className="navbar-links">
          <li>
            <a href="#how-it-works" onClick={(e) => {
              e.preventDefault();
              scrollToSection('how-it-works');
            }}>
              Comment ça marche
            </a>
          </li>
          <li>
            <a href="#features" onClick={(e) => {
              e.preventDefault();
              scrollToSection('features');
            }}>
              Fonctionnalités
            </a>
          </li>
          <li>
            <a href="#report" onClick={(e) => {
              e.preventDefault();
              scrollToSection('report');
            }}>
              Rapport
            </a>
          </li>
          <li>
            <button className="nav-btn-primary" onClick={onStartAudit}>
              Lancer un audit
            </button>
          </li>
        </ul>

        {/* Mobile Menu Button */}
        <button className="mobile-menu-btn" onClick={toggleMobileMenu}>
          <span className="hamburger-line"></span>
          <span className="hamburger-line"></span>
          <span className="hamburger-line"></span>
        </button>
      </div>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <div className="mobile-menu">
          <ul>
            <li>
              <a href="#how-it-works" onClick={(e) => {
                e.preventDefault();
                scrollToSection('how-it-works');
              }}>
                Comment ça marche
              </a>
            </li>
            <li>
              <a href="#features" onClick={(e) => {
                e.preventDefault();
                scrollToSection('features');
              }}>
                Fonctionnalités
              </a>
            </li>
            <li>
              <a href="#report" onClick={(e) => {
                e.preventDefault();
                scrollToSection('report');
              }}>
                Rapport
              </a>
            </li>
            <li>
              <button className="nav-btn-primary mobile" onClick={onStartAudit}>
                Lancer un audit
              </button>
            </li>
          </ul>
        </div>
      )}
    </nav>
  );
};

export default Navbar;