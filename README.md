# 🛡️ Adaptive Log Analyst

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19.1.1-61DAFB.svg)](https://reactjs.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-000000.svg)](https://flask.palletsprojects.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

> **Un serious game educativo per la formazione in cybersecurity attraverso l'analisi di log di sicurezza realistici**

Adaptive Log Analyst è un gioco interattivo progettato per sviluppare competenze pratiche nell'analisi dei log di sicurezza informatica. Gli utenti analizzano eventi realistici, identificano tecniche di attacco secondo il framework MITRE ATT&CK e scelgono strategie di mitigazione appropriate.

---

## 🎯 **Caratteristiche Principali**

### 🧠 **Sistema Adattivo Intelligente**
- **Difficoltà dinamica** basata su score, streak e accuracy dell'utente
- **Timer variabile** (60s → 45s → 30s) che si adatta al livello di competenza
- **Algoritmo di machine learning** per personalizzare l'esperienza educativa

### 📊 **Database Realistico**
- **Log autentici** da SSH, EDR, IDS/IPS, Sysmon e Network Security tools
- **Scenari graduali** da attacchi basic (brute force) ad advanced (APT techniques)
- **Metadati contestuali** (source, severity, timestamp) per analisi complete

### 🎮 **Gamification Avanzata**
- **Sistema di punteggio** con bonus temporali e streak multipliers
- **Progressione livelli** con unlock di contenuti avanzati
- **Statistiche real-time** (accuracy, best streak, favorite difficulty)
- **Feedback educativo** con spiegazioni dettagliate post-analisi

### 🔗 **Framework Integration**
- **MITRE ATT&CK** mapping automatico per ogni tecnica rilevata
- **Cyber Kill Chain** correlazione per comprensione fasi di attacco
- **Best Practices** di incident response e threat hunting

---

## 🚀 **Quick Start**

```bash
# Clone del repository
git clone https://github.com/your-username/adaptive-log-analyst.git
cd adaptive-log-analyst

# Setup Backend (Flask)
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py

# Setup Frontend (React) - Terminal separato
cd ../frontend
npm install
npm run dev
```

**🌐 Accesso:** `http://localhost:5173` (Frontend) + `http://localhost:5000` (API)

---

## 📋 **Installazione Dettagliata**

### **Prerequisiti**
- **Python 3.8+** con pip installato
- **Node.js 18+** e npm/yarn
- **Git** per version control

### **Backend Setup**
```bash
cd backend/

# Creazione ambiente virtuale
python -m venv venv

# Attivazione ambiente
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Installazione dipendenze
pip install -r requirements.txt

# Verifica installazione
python -c "import flask; print('Flask version:', flask.__version__)"

# Avvio server di sviluppo
python app.py
```

**✅ Backend attivo su:** `http://localhost:5000`

### **Frontend Setup**
```bash
cd frontend/

# Installazione dipendenze
npm install

# Verifica configurazione
npm list react react-dom

# Avvio development server
npm run dev
```

**✅ Frontend attivo su:** `http://localhost:5173`

---

## 🏗️ **Architettura del Sistema**

```
📦 Adaptive Log Analyst
├── 🔙 Backend (Flask)
│   ├── 🐍 app.py                 # Server principale e API routes
│   ├── 📊 logs_database          # Repository log categorizzati per difficoltà
│   ├── 🎯 mitre_mapping          # Correlazione eventi → ATT&CK techniques
│   ├── 🤖 adaptive_engine        # Algoritmo calcolo difficoltà dinamica
│   └── ✅ validation_system      # Scoring e feedback educativo
│
├── 🎨 Frontend (React)
│   ├── ⚛️ src/App.jsx            # Componente principale e game logic
│   ├── 🎮 game_mechanics         # Timer, scoring, progression system
│   ├── 📱 ui_components          # Log viewer, MITRE selector, feedback modal
│   └── 🎨 responsive_design      # CSS moderno con dark theme
│
└── 🔗 API Communication
    ├── 📡 RESTful endpoints      # /get-log, /validate, /adapt-difficulty
    ├── 📱 Session management     # User tracking e statistics
    └── 🛡️ Error handling        # Fallback offline mode
```

---

## 🎲 **Meccaniche di Gioco**

### **Difficoltà Adattiva**
```python
# Algoritmo di calcolo automatico
performance_score = (score * 0.3) + (streak * 10) + (accuracy * 0.4)

if performance_score < 50:    difficulty = 'Easy'    # Timer: 60s
elif performance_score < 150: difficulty = 'Medium'  # Timer: 45s
else:                         difficulty = 'Hard'    # Timer: 30s
```

### **Sistema di Punteggio**
| Livello | Punti Base | Bonus Tempo | Streak Multiplier |
|---------|------------|-------------|-------------------|
| Easy    | 10 pts     | 0.5x/sec    | +5 pts per streak |
| Medium  | 25 pts     | 0.5x/sec    | +10 pts per streak|
| Hard    | 50 pts     | 0.5x/sec    | +20 pts per streak|

### **MITRE ATT&CK Coverage**
<details>
<summary>📚 <strong>Tecniche Implementate per Livello</strong></summary>

**🟢 Easy Level:**
- `T1110` - Brute Force (Credential Access)
- `T1046` - Network Service Discovery (Discovery)
- `T1078` - Valid Accounts (Initial Access)

**🟡 Medium Level:**
- `T1059.001` - PowerShell (Execution)
- `T1547.001` - Registry Run Keys (Persistence)
- `T1055` - Process Injection (Defense Evasion)

**🔴 Hard Level:**
- `T1003.001` - LSASS Memory (Credential Access)
- `T1071.001` - Web Protocols (Command and Control)
- `T1486` - Data Encrypted for Impact (Impact)

</details>

---

## 🔧 **API Reference**

### **Endpoints Principali**

#### `POST /api/get-log`
Genera un nuovo log di sicurezza basato sulla difficoltà adattiva.

```javascript
// Request
{
  "difficulty": "medium",
  "session_id": "user_abc123",
  "stats": {
    "score": 150,
    "streak": 3,
    "accuracy": 85
  }
}

// Response
{
  "log": {
    "id": 3,
    "raw": "PowerShell execution with encoded command...",
    "source": "EDR System",
    "severity": "High",
    "timestamp": "2024-03-15 16:45:12",
    "metadata": { ... }
  },
  "mitre_options": [...],
  "mitigation_options": [...],
  "time_limit": 45
}
```

#### `POST /api/validate`
Valida la risposta dell'utente e fornisce feedback educativo.

```javascript
// Request
{
  "session_id": "user_abc123",
  "selected_mitre": "T1059.001",
  "selected_mitigation": "isolate_host",
  "time_remaining": 23,
  "difficulty": "medium"
}

// Response
{
  "is_correct": true,
  "points": 36,
  "explanation": "PowerShell execution indica tecnica T1059.001...",
  "correct_mitre": "T1059.001",
  "correct_mitigation": "isolate_host"
}
```

---

## 🎨 **Personalizzazione e Estensioni**

### **Aggiungere Nuovi Log**
```python
# In backend/app.py - LOGS_DATABASE
LOGS_DATABASE['custom'] = [
    {
        'id': 100,
        'raw': 'Il tuo log personalizzato qui...',
        'source': 'Custom Security Tool',
        'severity': 'Critical',
        'correctMitre': 'T1234',
        'correctMitigation': 'custom_action',
        'explanation': 'Spiegazione educativa...'
    }
]
```

### **Nuove Tecniche MITRE**
```python
# Estensione MITRE_OPTIONS
MITRE_OPTIONS['expert'] = [
    {
        'id': 'T1234',
        'name': 'Advanced Technique',
        'tactic': 'Custom Tactic'
    }
]
```

### **Tema UI Personalizzato**
```css
/* In frontend/src/App.css */
:root {
  --primary-gradient: linear-gradient(135deg, #your-color 0%, #your-color-2 100%);
  --background-primary: #your-dark-color;
  --text-primary: #your-light-color;
}
```

---

## 🤝 **Contributing**

Contributi sono benvenuti! Per partecipare:

1. **Fork** il repository
2. **Crea** un feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** le modifiche (`git commit -m 'Add amazing feature'`)
4. **Push** al branch (`git push origin feature/amazing-feature`)
5. **Apri** una Pull Request

### **Development Guidelines**
- **Code Style:** Seguire PEP 8 per Python, ESLint per JavaScript
- **Testing:** Aggiungere test per nuove features
- **Documentation:** Documentare API changes e breaking changes
- **Security:** Non committare API keys o dati sensibili

---

## 📖 **Roadmap**

### **🔜 Prossime Features**
- [ ] **Multiplayer Mode** - Competizioni team-based
- [ ] **Real SIEM Integration** - Connessione Splunk/QRadar
- [ ] **Machine Learning** - AI-powered difficulty tuning
- [ ] **Mobile App** - React Native implementation
- [ ] **Certification Tracking** - Progress verso certificate professionali

### **🎯 Long-term Vision**
- [ ] **Corporate Training Platform** - Enterprise deployment
- [ ] **VR/AR Integration** - Immersive SOC simulation
- [ ] **Threat Intel Feed** - Real-time IoC updates
- [ ] **Global Leaderboards** - Worldwide competition

---

## 📚 **Risorse Educative**

### **📖 Learning Resources**
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Incident Response Guide](https://www.sans.org/white-papers/incident-response/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### **🛠️ Technical Documentation**
- [Flask Documentation](https://flask.palletsprojects.com/)
- [React Documentation](https://react.dev/)
- [MITRE ATT&CK APIs](https://github.com/mitre-attack)

---

## 🐛 **Troubleshooting**

<details>
<summary><strong>❌ Backend non si avvia</strong></summary>

```bash
# Verifica Python version
python --version  # Deve essere 3.8+

# Reinstalla dipendenze
pip install --upgrade -r requirements.txt

# Check porta occupata
netstat -an | grep 5000
```
</details>

<details>
<summary><strong>❌ Frontend errori di build</strong></summary>

```bash
# Clear cache e reinstalla
rm -rf node_modules package-lock.json
npm install

# Verifica Node version
node --version  # Deve essere 18+
```
</details>

<details>
<summary><strong>❌ CORS Issues</strong></summary>

Assicurati che Flask CORS sia configurato correttamente:
```python
from flask_cors import CORS
CORS(app)  # In backend/app.py
```
</details>

---

## 📄 **License**

Questo progetto è rilasciato sotto [MIT License](LICENSE).

```
MIT License - Copyright (c) 2024 Adaptive Log Analyst Team
Permesso di uso, copia, modifica e distribuzione concesso.
```

---

## 👥 **Team & Credits**

### **Core Developers**
- **[Maelbru]** - *Project Lead, Frontend Development and Backend Architecture*

### **Special Thanks**
- **MITRE Corporation** - ATT&CK Framework
- **Flask Community** - Web framework
- **React Team** - Frontend library
- **Cybersecurity Community** - Domain expertise e feedback

<div align="center">

**⭐ Se questo progetto ti è utile, lascia una stella su GitHub! ⭐**

*Adaptive Log Analyst - Trasformare la cybersecurity education attraverso il gaming*

[![GitHub stars](https://img.shields.io/github/stars/your-username/adaptive-log-analyst?style=social)](https://github.com/your-username/adaptive-log-analyst/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/your-username/adaptive-log-analyst?style=social)](https://github.com/your-username/adaptive-log-analyst/network)

</div>
