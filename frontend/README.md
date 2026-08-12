# OddNet — écran de validation HITL

## Backend (depuis la racine du projet, pas depuis frontend/)

```
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

## Frontend

```
cd frontend
npm install
npm run dev
```

Ouvre http://localhost:5173, remplis le formulaire (entreprise / ingénieur /
objectif), l'audit démarre côté backend. Dès qu'une commande a besoin d'une
validation, elle s'affiche automatiquement (poll toutes les 2s) avec les
trois actions Approve / Reject / Modify.

## Comment ça marche

- `backend/api/main.py` lance ton graphe LangGraph existant
  (`core_langgraph/graph.py`) dans un thread, avec un `audit_id`.
- `backend/api/hitl_bridge.py` remplace les `input()` de
  `backend/agents/human_validation_agent.py` par une attente sur
  `threading.Event`, débloquée quand le frontend appelle
  `POST /audits/{id}/validate`. Le mode CLI (`backend/main.py`) n'est pas
  touché — il continue de fonctionner avec `input()` comme avant.
- Le frontend ne fait que 3 appels : `POST /audits`, `GET /audits/{id}`
  (poll), `POST /audits/{id}/validate`.

C'est volontairement basique : une seule page, pas de routeur, pas de state
manager. À étendre (dashboard, historique des audits, WebSocket au lieu du
poll) une fois que ce flux de base tourne chez toi.
