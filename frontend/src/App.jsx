/*
 * ADAPTIVE LOG ANALYST - SERIOUS GAME
 * Obiettivo: Analizzare log di sicurezza e identificare tecniche MITRE ATT&CK
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import axios from 'axios' // Libreria per chiamate HTTP
import './App.css'

// ============================================================================
// CONFIGURAZIONE
// ============================================================================

const API_URL = 'http://localhost:5000/api' // URL base per le chiamate API al backend Flask
const SESSION_ID = 'user_' + Math.random().toString(36).substr(2, 9)
// ID di sessione univoco per ogni utente (Formato: "user_" + stringa casuale di 9 caratteri; serve per tracciare la sessione lato backend) 

// ============================================================================
// DATI MOCK (FALLBACK)
// ============================================================================

/*
 * Dati di fallback utilizzati quando l'API non è disponibile
 * Permette al gioco di funzionare anche offline
 */

const mockData = {
  // Log di esempio per ogni livello di difficoltà
  logs: {
    easy: [
      {
        id: 1,
        // Log grezzo come apparirebbe in un vero sistema
        raw: "2024-03-15 14:23:45 [ALERT] Failed login attempt from IP 192.168.1.105 - User: admin - Attempts: 5",
        source: "SSH Server", // Sistema che ha generato il log
        severity: "Medium", // Livello di gravità
        timestamp: "2024-03-15 14:23:45",
        metadata: {  // Dati strutturati estratti dal log
          ip: "192.168.1.105",
          user: "admin",
          service: "SSH",
          attempts: 5
        }
      }
    ]
  },

  // Opzioni MITRE ATT&CK tra cui l'utente deve scegliere
  mitreOptions: {
    easy: [
      {
        id: "T1110",                  // Codice tecnica MITRE
        name: "Brute Force",          // Nome descrittivo
        tactic: "Credential Access"   // Categoria tattica
      },
      { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
      { id: "T1090", name: "Proxy", tactic: "Command and Control" },
      { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" }
    ]
  },

  // Strategie di mitigazione disponibili
  mitigationOptions: [
    'block_ip',           // Bloccare l'IP a livello firewall
    'implement_mfa',      // Implementare autenticazione multi-fattore
    'isolate_host',       // Isolare l'host dalla rete
    'forensic_analysis'   // Analisi forense approfondita
  ]
}

// ============================================================================
// SISTEMA DI DIFFICOLTÀ ADATTIVA
// ============================================================================

/**
 * Oggetto che gestisce l'adattamento dinamico della difficoltà
 * Il gioco diventa più difficile man mano che il giocatore migliora
 */
const AdaptiveDifficulty = {
  /**
   * Calcola il prossimo livello di difficoltà basandosi sulle performance
   * @param {number} score - Punteggio totale del giocatore
   * @param {number} streak - Serie di risposte corrette consecutive
   * @param {number} accuracy - Percentuale di accuratezza (0-100)
   * @returns {string} 'easy', 'medium', o 'hard'
   */
  calculateNextDifficulty: (score, streak, accuracy) => {
    const performanceScore = (score * 0.3) + (streak * 10) + (accuracy * 0.4)
    // Formula pesata che combina tre metriche di performance (score contribuisce per il 30%, streak per punti fissi, accuracy per il 40%)

    // Soglie per determinare la difficoltà
    if (performanceScore < 50) return 'easy'
    if (performanceScore < 150) return 'medium'
    return 'hard'
  },

  /**
   * Ottiene il limite di tempo in base alla difficoltà
   * @param {string} difficulty - Livello di difficoltà
   * @returns {number} Secondi disponibili per rispondere
   */
  getTimeLimit: (difficulty) => {
    const limits = { easy: 60, medium: 45, hard: 30 }
    return limits[difficulty] || 60
  },

  /**
   * Calcola i punti guadagnati per una risposta
   * @param {string} difficulty - Livello di difficoltà
   * @param {number} timeRemaining - Secondi rimasti quando si risponde
   * @param {boolean} isCorrect - Se la risposta è corretta
   * @returns {number} Punti totali guadagnati
   */
  getPoints: (difficulty, timeRemaining, isCorrect) => {
    if (!isCorrect) return 0 // Nessun punto per risposte errate

    // Punti base per difficoltà
    const basePoints = { easy: 10, medium: 25, hard: 50 }
    // Bonus tempo: più veloce risponde, più punti extra ottiene
    const timeBonus = Math.floor(timeRemaining * 0.5)
    return basePoints[difficulty] + timeBonus
  }
}

// ============================================================================
// COMPONENTE PRINCIPALE
// ============================================================================

/**
 * Componente React principale che gestisce l'intero gioco
 */

function App() {

  // ========================================
  // STATE MANAGEMENT (Stati del componente)
  // ========================================

  // Stati generali del gioco
  const [gameState, setGameState] = useState('welcome')

  // Statistiche del giocatore
  const [score, setScore] = useState(0)
  const [streak, setStreak] = useState(0)
  const [level, setLevel] = useState(1)
  const [accuracy, setAccuracy] = useState(100)
  const [totalAttempts, setTotalAttempts] = useState(0)
  const [correctAttempts, setCorrectAttempts] = useState(0)

  // Stati del round corrente
  const [currentLog, setCurrentLog] = useState(null)
  const [difficulty, setDifficulty] = useState('easy')
  const [timeRemaining, setTimeRemaining] = useState(60)
  const [selectedMitre, setSelectedMitre] = useState(null)
  const [selectedMitigation, setSelectedMitigation] = useState(null)
  const [mitreOptions, setMitreOptions] = useState([])
  const [mitigationOptions, setMitigationOptions] = useState([])

  // Stati UI e feedback
  const [feedback, setFeedback] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [apiError, setApiError] = useState(false)

  // Riferimenti
  const timerRef = useRef(null)
  const [isTimerActive, setIsTimerActive] = useState(false)

  // ========================================
  // FUNZIONI HELPER
  // ========================================

  /**
   * Funzione di fallback che usa dati mock quando l'API non è disponibile
   * @param {string} difficulty - Livello di difficoltà
   */
  const useMockData = (difficulty) => {
    console.log('Using mock data as fallback')

    // Seleziona log casuali dai dati mock (soluzione temporanea)
    const logs = mockData.logs[difficulty] || mockData.logs.easy
    const randomLog = logs[Math.floor(Math.random() * logs.length)]

    // Imposta tutti gli stati necessari per giocare offline
    setCurrentLog(randomLog)
    setMitreOptions(mockData.mitreOptions[difficulty] || mockData.mitreOptions.easy)
    setMitigationOptions(mockData.mitigationOptions)

    // Configura timer e avvia il gioco
    const timeLimit = AdaptiveDifficulty.getTimeLimit(difficulty)
    setTimeRemaining(timeLimit)
    setIsTimerActive(true)
    setGameState('playing')
    setApiError(true) // Segnala che siamo in modalità offline
  }

  // ========================================
  // FUNZIONE PRINCIPALE: AVVIO NUOVO ROUND
  // ========================================

  /**
   * Avvia un nuovo round di gioco
   * Le dipendenze [score, streak, accuracy] fanno sì che la funzione
   * si aggiorni quando questi valori cambiano
   */
  const startNewRound = useCallback(async () => {
    // Mostra indicatore di caricamento
    setIsLoading(true)
    setApiError(false)

    // STEP 1: Calcola la difficoltà adattiva
    const newDifficulty = AdaptiveDifficulty.calculateNextDifficulty(score, streak, accuracy)
    setDifficulty(newDifficulty)

    try {
      console.log('Recupero del nuovo registro da API...')

      // STEP 2: Chiamata API al backend Flask
      const response = await axios.post(`${API_URL}/get-log`, {
        // Payload della richiesta
        difficulty: newDifficulty,
        session_id: SESSION_ID,
        stats: {
          score,
          streak,
          accuracy
        } // Invia statistiche per analisi
      }, {
        timeout: 5000 // Timeout di 5 secondi per evitare attese infinite
      })

      console.log('Risposta API:', response.data)

      // STEP 3: Validazione della risposta
      if (response.data && response.data.log) {
        // Successo: usa i dati dall'API
        setCurrentLog(response.data.log)
        setMitreOptions(response.data.mitre_options || [])
        setMitigationOptions(response.data.mitigation_options || [])
        setTimeRemaining(response.data.time_limit || 60)
        setIsTimerActive(true)
        setGameState('playing')
      } else {
        throw new Error('Invalid response format')
      }

    } catch (error) {
      // STEP 4: Gestione errori - usa dati mock come fallback
      console.error('Error fetching log:', error)
      console.log('Falling back to mock data')

      useMockData(newDifficulty)
    } finally {
      // STEP 5: Cleanup - sempre eseguito
      setIsLoading(false)
      setSelectedMitre(null) // Reset selezioni
      setSelectedMitigation(null)
    }
  }, [score, streak, accuracy]) // Dipendenze del useCallback

  // ========================================
  // EFFECT: GESTIONE TIMER
  // ========================================

  /**
   * useEffect per gestire il countdown del timer
   * Si attiva quando timeRemaining o isTimerActive cambiano
   */
  useEffect(() => {
    if (isTimerActive && timeRemaining > 0) {
      // Crea un timeout che decrementa il timer dopo 1 secondo
      timerRef.current = setTimeout(() => {
        setTimeRemaining(prev => prev - 1)  // Decrementa di 1 secondo
      }, 1000)
    } else if (timeRemaining === 0 && isTimerActive) {
      // Tempo scaduto: invia automaticamente la risposta
      handleSubmit(true) // true indica che il tempo è scaduto
    }

    // Cleanup: cancella il timeout quando il componente si smonta o quando le dipendenze cambiano
    return () => clearTimeout(timerRef.current)
  }, [timeRemaining, isTimerActive]) // Dipendenze dell'effect

  // ========================================
  // FUNZIONE: GESTIONE INVIO RISPOSTA
  // ========================================

  /**
   * Gestisce l'invio della risposta dell'utente
   * @param {boolean} timeExpired - Se true, il tempo è scaduto
   */
  const handleSubmit = async (timeExpired = false) => {
    // Ferma il timer
    setIsTimerActive(false)
    setIsLoading(true)

    try {
      if (!apiError) {
        // MODALITÀ ONLINE: Valida con l'API
        const response = await axios.post(`${API_URL}/validate`, {
          session_id: SESSION_ID,
          selected_mitre: selectedMitre,
          selected_mitigation: selectedMitigation,
          time_remaining: timeRemaining,
          difficulty
        }, {
          timeout: 5000
        })

        const validationResult = response.data

        // Aggiorna le statistiche basandosi sulla risposta del server
        setScore(prev => prev + validationResult.points)
        setTotalAttempts(prev => prev + 1)

        if (validationResult.is_correct) {
          setStreak(prev => prev + 1) // Incrementa serie
          setCorrectAttempts(prev => prev + 1)
        } else {
          setStreak(0) // Reset serie se sbaglia
        }

        // Ricalcola accuratezza (percentuale di risposte corrette)
        const newAccuracy = Math.round(((correctAttempts + (validationResult.is_correct ? 1 : 0)) / (totalAttempts + 1)) * 100)
        setAccuracy(newAccuracy)

        // Controlla avanzamento di livello (ogni 100 punti)
        if (score + validationResult.points >= level * 100) {
          setLevel(prev => prev + 1)
        }

        // Prepara oggetto feedback per mostrare i risultati
        setFeedback({
          isCorrect: validationResult.is_correct,
          timeExpired,
          correctMitre: validationResult.correct_mitre,
          correctMitigation: validationResult.correct_mitigation,
          selectedMitre,
          selectedMitigation,
          points: validationResult.points,
          explanation: validationResult.explanation
        })

      } else {
        // MODALITÀ OFFLINE: Validazione mock locale
        console.log('Using mock validation')

        // Simulazione semplificata (per test)
        const points = timeExpired ? 0 : AdaptiveDifficulty.getPoints(difficulty, timeRemaining, true)

        // Aggiorna statistiche localmente
        setScore(prev => prev + points)
        setTotalAttempts(prev => prev + 1)
        setStreak(prev => prev + 1)
        setCorrectAttempts(prev => prev + 1)

        const newAccuracy = Math.round(((correctAttempts + 1) / (totalAttempts + 1)) * 100)
        setAccuracy(newAccuracy)

        // Feedback mock
        setFeedback({
          isCorrect: true,
          timeExpired,
          correctMitre: selectedMitre || 'T1110',
          correctMitigation: selectedMitigation || 'block_ip',
          selectedMitre,
          selectedMitigation,
          points,
          explanation: 'Mock validation - API not available'
        })
      }

    } catch (error) {
      // Gestione errori di validazione
      console.error('Validation error:', error)

      setFeedback({
        isCorrect: false,
        timeExpired,
        correctMitre: 'Unknown',
        correctMitigation: 'Unknown',
        selectedMitre,
        selectedMitigation,
        points: 0,
        explanation: 'Validation error - please try again'
      })
    } finally {
      setIsLoading(false)
      setGameState('feedback') // Passa alla schermata di feedback
    }
  }

  // ========================================
  // RENDERING CONDIZIONALE
  // ========================================

  /**
   * SCHERMATA DI BENVENUTO
   */
  if (gameState === 'welcome') {
    return (
      <div className="welcome-screen">
        <div className="welcome-content">
          <div className="welcome-logo">🛡️</div>
          <h1 className="welcome-title">Adaptive Log Analyst</h1>
          <p className="welcome-subtitle">
            Metti alla prova le tue competenze in materia di sicurezza informatica analizzando i log di sicurezza reali. Identifica le tecniche MITRE ATT&CK e scegli le migliori strategie di mitigazione.
          </p>

          {/* Avviso modalità offline se API non disponibile */}
          {apiError && (
            <div style={{
              background: 'rgba(251, 191, 36, 0.1)',
              border: '1px solid #fbbf24',
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '20px',
              color: '#fbbf24'
            }}>
              ⚠️ Esecuzione in modalità offline (API non disponibile)
            </div>
          )}
          <button
            className="start-button"
            onClick={startNewRound}
            disabled={isLoading} // Disabilita durante caricamento
          >
            {isLoading ? 'Loading...' : 'Start Game'}
          </button>
        </div>
      </div>
    )
  }

  /**
   * MODAL DI FEEDBACK
   * Mostrato dopo ogni risposta per dare feedback all'utente
   */
  if (gameState === 'feedback' && feedback) {
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className={`modal-icon ${feedback.isCorrect ? 'success' : 'error'}`}>
            {/* Icona successo/errore */}
            {feedback.isCorrect ? '✓' : '✗'}
          </div>

          {/* Titolo del risultato */}
          <h2 className="modal-title">
            {feedback.timeExpired ? 'Tempo scaduto!' :
              feedback.isCorrect ? 'Corretta!' : 'Errata!'}
          </h2>

          {/* Messaggio principale */}
          <p className="modal-message">
            {feedback.isCorrect ?
              `Ottima analisi! Hai guadagnato ${feedback.points} punti.` :
              'Rivediamo la risposta corretta.'}
          </p>

          {/* Dettagli della risposta */}
          <div className="modal-details">
            <div className="detail-item">
              <span className="detail-label">Tecnica MITRE corretta:</span>
              <span className="detail-value">{feedback.correctMitre}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Tecnica MITRE scelta:</span>
              <span className="detail-value">
                {feedback.selectedMitre || 'Not selected'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Punti guadagnati:</span>
              <span className="detail-value">{feedback.points}</span>
            </div>
          </div>

          {/* Spiegazione educativa */}
          {feedback.explanation && (
            <p className="modal-message" style={{ fontSize: '14px', fontStyle: 'italic', marginTop: '15px' }}>
              {feedback.explanation}
            </p>
          )}

          {/* Bottone per prossimo round */}
          <button
            className="modal-button"
            onClick={startNewRound}
            disabled={isLoading}
          >
            {isLoading ? 'Loading...' : 'Next Log'}
          </button>
        </div>
      </div>
    )
  }

  /**
   * SCHERMATA DI GIOCO PRINCIPALE
   * L'interfaccia principale dove l'utente analizza i log
   */
  return (
    <div className="game-container">
      <header className="header">
        {/* Logo e nome del gioco */}
        <div className="logo">
          <div className="logo-icon">🛡️</div>
          <div className="logo-text">Adaptive Log Analyst</div>
        </div>

        {/* Barra delle statistiche in tempo reale */}
        <div className="stats-bar">
          <div className="stat-item">
            <span className="stat-label">Score</span>
            <span className="stat-value score">{score}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Streak</span>
            <span className="stat-value streak">{streak}🔥</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Accuracy</span>
            <span className="stat-value accuracy">{accuracy}%</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Level</span>
            <span className="stat-value level">{level}</span>
          </div>
        </div>

        {/* Indicatore modalità offline */}
        {apiError && (
          <div style={{
            padding: '8px 16px',
            background: 'rgba(251, 191, 36, 0.2)',
            border: '1px solid #fbbf24',
            borderRadius: '8px',
            fontSize: '14px',
            color: '#fbbf24'
          }}>
            Offline Mode
          </div>
        )}
      </header>

      {/* AREA DI GIOCO divisa in due colonne */}
      <div className="game-content">

        {/* COLONNA SINISTRA: Log da analizzare */}
        <div className="log-panel">
          <h2 className="panel-title">📋 Security Log Analysis</h2>

          {/* Timer countdown con cambio colore dinamico 
          (Rosso sotto i 10 secondi, Giallo sotto i 20 secondi) */}
          <div className="timer-container">
            <div className={`timer ${timeRemaining <= 10 ? 'critical' : timeRemaining <= 20 ? 'warning' : ''}`}>
              {timeRemaining}s
            </div>
          </div>

          {/* Mostra il log se disponibile */}
          {currentLog && (
            <>
              {/* Log grezzo in formato monospace */}
              <div className="log-content">
                <pre>{currentLog.raw}</pre>
              </div>

              {/* Metadata del log in griglia */}
              <div className="log-metadata">
                <div className="meta-item">
                  <span className="meta-label">Source:</span>
                  <span className="meta-value">{currentLog.source}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Severity:</span>
                  <span className="meta-value">{currentLog.severity}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Timestamp:</span>
                  <span className="meta-value">{currentLog.timestamp}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Log ID:</span>
                  <span className="meta-value">#{currentLog.id}</span>
                </div>
              </div>
            </>
          )}
        </div>

        {/* COLONNA DESTRA: Interfaccia di analisi */}
        <div className="analysis-panel">
          <h2 className="panel-title">🎯 Your Analysis</h2>
          
          {/* SEZIONE 1: Selezione tecnica MITRE */}
          <div className="mitre-selection">
            <h3 className="selection-title">📊 Select MITRE ATT&CK Technique</h3>
            <div className="mitre-options">
              {mitreOptions.map(option => (
                <div
                  key={option.id}
                  className={`mitre-option ${selectedMitre === option.id ? 'selected' : ''}`}
                  onClick={() => setSelectedMitre(option.id)}
                >
                  <div className="mitre-code">{option.id}</div>
                  <div className="mitre-name">{option.name}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="mitigation-selection">
            <h3 className="selection-title">🛡️ Choose Mitigation Strategy</h3>
            <div className="mitigation-options">
              {mitigationOptions.map(key => (
                <div
                  key={key}
                  className={`mitigation-option ${selectedMitigation === key ? 'selected' : ''}`}
                  onClick={() => setSelectedMitigation(key)}
                >
                  <div className="mitigation-text">{key.replace(/_/g, ' ').toUpperCase()}</div>
                </div>
              ))}
            </div>
          </div>

          <button
            className="submit-button"
            onClick={() => handleSubmit(false)}
            disabled={!selectedMitre || !selectedMitigation || isLoading}
          >
            {isLoading ? 'Submitting...' : 'Submit Analysis'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default App