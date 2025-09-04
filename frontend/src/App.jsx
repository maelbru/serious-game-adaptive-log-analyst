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

// Adaptive Difficulty System
const AdaptiveDifficulty = {
  calculateNextDifficulty: (score, streak, accuracy) => {
    const performanceScore = (score * 0.3) + (streak * 10) + (accuracy * 0.4)

    if (performanceScore < 50) return 'easy'
    if (performanceScore < 150) return 'medium'
    return 'hard'
  },

  getTimeLimit: (difficulty) => {
    const limits = { easy: 60, medium: 45, hard: 30 }
    return limits[difficulty] || 60
  },

  getPoints: (difficulty, timeRemaining, isCorrect) => {
    if (!isCorrect) return 0
    const basePoints = { easy: 10, medium: 25, hard: 50 }
    const timeBonus = Math.floor(timeRemaining * 0.5)
    return basePoints[difficulty] + timeBonus
  }
}

function App() {
  const [gameState, setGameState] = useState('welcome')
  const [score, setScore] = useState(0)
  const [streak, setStreak] = useState(0)
  const [level, setLevel] = useState(1)
  const [accuracy, setAccuracy] = useState(100)
  const [totalAttempts, setTotalAttempts] = useState(0)
  const [correctAttempts, setCorrectAttempts] = useState(0)

  const [currentLog, setCurrentLog] = useState(null)
  const [difficulty, setDifficulty] = useState('easy')
  const [timeRemaining, setTimeRemaining] = useState(60)
  const [selectedMitre, setSelectedMitre] = useState(null)
  const [selectedMitigation, setSelectedMitigation] = useState(null)
  const [mitreOptions, setMitreOptions] = useState([])
  const [mitigationOptions, setMitigationOptions] = useState([])
  const [feedback, setFeedback] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [apiError, setApiError] = useState(false)

  const timerRef = useRef(null)
  const [isTimerActive, setIsTimerActive] = useState(false)

  // Funzione per usare mock data se l'API fallisce
  const useMockData = (difficulty) => {
    console.log('Using mock data as fallback')
    const logs = mockData.logs[difficulty] || mockData.logs.easy
    const randomLog = logs[Math.floor(Math.random() * logs.length)]

    setCurrentLog(randomLog)
    setMitreOptions(mockData.mitreOptions[difficulty] || mockData.mitreOptions.easy)
    setMitigationOptions(mockData.mitigationOptions)

    const timeLimit = AdaptiveDifficulty.getTimeLimit(difficulty)
    setTimeRemaining(timeLimit)
    setIsTimerActive(true)
    setGameState('playing')
    setApiError(true)
  }

  // Start new round - con gestione errori migliorata
  const startNewRound = useCallback(async () => {
    setIsLoading(true)
    setApiError(false)

    const newDifficulty = AdaptiveDifficulty.calculateNextDifficulty(score, streak, accuracy)
    setDifficulty(newDifficulty)

    try {
      console.log('Fetching new log from API...')

      const response = await axios.post(`${API_URL}/get-log`, {
        difficulty: newDifficulty,
        session_id: SESSION_ID,
        stats: {
          score,
          streak,
          accuracy
        }
      }, {
        timeout: 5000 // 5 secondi di timeout
      })

      console.log('API Response:', response.data)

      if (response.data && response.data.log) {
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
      console.error('Error fetching log:', error)
      console.log('Falling back to mock data')

      // Usa mock data come fallback
      useMockData(newDifficulty)
    } finally {
      setIsLoading(false)
      setSelectedMitre(null)
      setSelectedMitigation(null)
    }
  }, [score, streak, accuracy])

  // Timer effect
  useEffect(() => {
    if (isTimerActive && timeRemaining > 0) {
      timerRef.current = setTimeout(() => {
        setTimeRemaining(prev => prev - 1)
      }, 1000)
    } else if (timeRemaining === 0 && isTimerActive) {
      handleSubmit(true)
    }

    return () => clearTimeout(timerRef.current)
  }, [timeRemaining, isTimerActive])

  // Handle submission - con chiamata API o mock
  const handleSubmit = async (timeExpired = false) => {
    setIsTimerActive(false)
    setIsLoading(true)

    try {
      if (!apiError) {
        // Prova a validare con l'API
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

        // Update stats
        setScore(prev => prev + validationResult.points)
        setTotalAttempts(prev => prev + 1)

        if (validationResult.is_correct) {
          setStreak(prev => prev + 1)
          setCorrectAttempts(prev => prev + 1)
        } else {
          setStreak(0)
        }

        const newAccuracy = Math.round(((correctAttempts + (validationResult.is_correct ? 1 : 0)) / (totalAttempts + 1)) * 100)
        setAccuracy(newAccuracy)

        if (score + validationResult.points >= level * 100) {
          setLevel(prev => prev + 1)
        }

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
        // Validazione mock locale
        console.log('Using mock validation')

        // Simulazione di validazione (sempre corretta per test)
        const points = timeExpired ? 0 : AdaptiveDifficulty.getPoints(difficulty, timeRemaining, true)

        setScore(prev => prev + points)
        setTotalAttempts(prev => prev + 1)
        setStreak(prev => prev + 1)
        setCorrectAttempts(prev => prev + 1)

        const newAccuracy = Math.round(((correctAttempts + 1) / (totalAttempts + 1)) * 100)
        setAccuracy(newAccuracy)

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
      console.error('Validation error:', error)

      // Fallback validation
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
      setGameState('feedback')
    }
  }

  // Welcome Screen
  if (gameState === 'welcome') {
    return (
      <div className="welcome-screen">
        <div className="welcome-content">
          <div className="welcome-logo">🛡️</div>
          <h1 className="welcome-title">Adaptive Log Analyst</h1>
          <p className="welcome-subtitle">
            Test your cybersecurity skills by analyzing real-world security logs.
            Identify MITRE ATT&CK techniques and choose the best mitigation strategies.
          </p>
          {apiError && (
            <div style={{
              background: 'rgba(251, 191, 36, 0.1)',
              border: '1px solid #fbbf24',
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '20px',
              color: '#fbbf24'
            }}>
              ⚠️ Running in offline mode (API not available)
            </div>
          )}
          <button
            className="start-button"
            onClick={startNewRound}
            disabled={isLoading}
          >
            {isLoading ? 'Loading...' : 'Start Game'}
          </button>
        </div>
      </div>
    )
  }

  // Feedback Modal
  if (gameState === 'feedback' && feedback) {
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className={`modal-icon ${feedback.isCorrect ? 'success' : 'error'}`}>
            {feedback.isCorrect ? '✓' : '✗'}
          </div>
          <h2 className="modal-title">
            {feedback.timeExpired ? 'Time Expired!' :
              feedback.isCorrect ? 'Correct!' : 'Incorrect'}
          </h2>
          <p className="modal-message">
            {feedback.isCorrect ?
              `Excellent analysis! You earned ${feedback.points} points.` :
              'Let\'s review the correct answer.'}
          </p>
          <div className="modal-details">
            <div className="detail-item">
              <span className="detail-label">Correct MITRE:</span>
              <span className="detail-value">{feedback.correctMitre}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Your MITRE:</span>
              <span className="detail-value">
                {feedback.selectedMitre || 'Not selected'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Points Earned:</span>
              <span className="detail-value">{feedback.points}</span>
            </div>
          </div>
          {feedback.explanation && (
            <p className="modal-message" style={{ fontSize: '14px', fontStyle: 'italic', marginTop: '15px' }}>
              {feedback.explanation}
            </p>
          )}
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

  // Main Game Screen
  return (
    <div className="game-container">
      <header className="header">
        <div className="logo">
          <div className="logo-icon">🛡️</div>
          <div className="logo-text">Adaptive Log Analyst</div>
        </div>

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

      <div className="game-content">
        <div className="log-panel">
          <h2 className="panel-title">📋 Security Log Analysis</h2>

          <div className="timer-container">
            <div className={`timer ${timeRemaining <= 10 ? 'critical' : timeRemaining <= 20 ? 'warning' : ''}`}>
              {timeRemaining}s
            </div>
          </div>

          {currentLog && (
            <>
              <div className="log-content">
                <pre>{currentLog.raw}</pre>
              </div>

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

        <div className="analysis-panel">
          <h2 className="panel-title">🎯 Your Analysis</h2>

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