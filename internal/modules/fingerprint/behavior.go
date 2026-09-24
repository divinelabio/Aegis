package fingerprint

import (
	"math"
)

// BehaviorAnalysisResult holds behavioral analysis scores
type BehaviorAnalysisResult struct {
	MouseScore    int // 0-100, higher = more human-like
	KeyboardScore int // 0-100, higher = more human-like
	OverallScore  int // Combined score
	Reasons       []string
}

// AnalyzeBehavior analyzes behavioral data for bot detection
func AnalyzeBehavior(data BehaviorData) *BehaviorAnalysisResult {
	result := &BehaviorAnalysisResult{
		MouseScore:    100,
		KeyboardScore: 100,
		Reasons:       make([]string, 0),
	}

	// Analyze mouse behavior
	if data.HasMouse && len(data.Events.Mouse) > 0 {
		result.MouseScore = analyzeMouseEvents(data.Events.Mouse)
		if result.MouseScore < 30 {
			result.Reasons = append(result.Reasons, "Bot-like mouse movement")
		}
	} else if data.MMoves > 0 {
		result.MouseScore = analyzeBehaviorVector(data)
		if result.MouseScore < 35 {
			result.Reasons = append(result.Reasons, "Behavior vector indicates synthetic interaction")
		}
	} else if !data.HasMouse {
		// No mouse events is suspicious for desktop
		result.MouseScore = 50
		result.Reasons = append(result.Reasons, "No mouse events detected")
	}

	// Analyze keyboard behavior
	if data.HasKeyboard && len(data.Events.Keys) > 0 {
		result.KeyboardScore = analyzeKeyboardEvents(data.Events.Keys)
		if result.KeyboardScore < 30 {
			result.Reasons = append(result.Reasons, "Bot-like keyboard patterns")
		}
	} else if data.KCount > 0 {
		result.KeyboardScore = analyzeKeyboardVector(data)
		if result.KeyboardScore < 35 {
			result.Reasons = append(result.Reasons, "Keyboard cadence looks automated")
		}
	}

	// Calculate overall score (weighted average)
	result.OverallScore = (result.MouseScore*60 + result.KeyboardScore*40) / 100

	if data.Time > 0 && result.OverallScore > 0 {
		if data.Time < 2 && (data.MMoves > 12 || data.Clicks > 2 || data.KCount > 3) {
			result.OverallScore -= 18
			result.Reasons = append(result.Reasons, "Interaction burst completed too quickly")
		} else if data.Time > 0 && data.Time < 4 && data.SDepth == 0 && data.Clicks == 0 && data.KCount == 0 && data.MMoves < 2 {
			result.OverallScore -= 10
			result.Reasons = append(result.Reasons, "Session timeline lacks natural pauses or exploration")
		}
	}

	if result.OverallScore < 0 {
		result.OverallScore = 0
	}

	return result
}

// analyzeMouseEvents scores mouse behavior (higher = more human-like)
func analyzeMouseEvents(events []Event) int {
	if len(events) < 3 {
		return 30 // Too few events to analyze
	}

	score := 100

	// 1. Calculate path entropy (randomness)
	entropy := calculateMouseEntropy(events)
	if entropy < 0.3 {
		score -= 40 // Very linear path = bot-like
	} else if entropy < 0.5 {
		score -= 20 // Somewhat linear
	}

	// 2. Calculate speed variance
	speedVariance := calculateSpeedVariance(events)
	if speedVariance < 0.1 {
		score -= 30 // Constant speed = bot-like
	} else if speedVariance < 0.3 {
		score -= 15
	}

	// 3. Check timing patterns
	timingScore := analyzeMouseTiming(events)
	score = (score + timingScore) / 2

	// 4. Human movement usually contains slight jitter even on mostly straight paths.
	if calculateMicroJitter(events) < 0.03 {
		score -= 12
	}

	// 5. Human acceleration is gradual rather than binary.
	if calculateAccelerationVariance(events) < 0.001 {
		score -= 15
	}

	// 6. Extremely straight movement is a common automation signature.
	if looksBezierLikeAutomation(events) {
		score -= 18
	}

	if score < 0 {
		score = 0
	}
	return score
}

// analyzeKeyboardEvents scores keyboard behavior
func analyzeKeyboardEvents(events []Event) int {
	if len(events) < 3 {
		return 50 // Too few events
	}

	score := 100

	// 1. Calculate inter-key timing variance
	timings := make([]float64, 0)
	for i := 1; i < len(events); i++ {
		delta := float64(events[i].T - events[i-1].T)
		if delta > 0 && delta < 5000 { // Ignore pauses > 5s
			timings = append(timings, delta)
		}
	}

	if len(timings) > 2 {
		variance := calculateVariance(timings)
		meanTiming := mean(timings)

		// Very regular timing = bot-like
		coefficientOfVariation := variance / meanTiming
		if coefficientOfVariation < 0.1 {
			score -= 40 // Machine-like regularity
		} else if coefficientOfVariation < 0.2 {
			score -= 20
		}

		// Too fast typing = bot-like
		if meanTiming < 30 { // < 30ms between keys
			score -= 30
		}
	}

	if score < 0 {
		score = 0
	}
	return score
}

// calculateMouseEntropy calculates path randomness (0 = linear, 1 = random)
func calculateMouseEntropy(events []Event) float64 {
	if len(events) < 3 {
		return 0.5
	}

	// Calculate angle changes between segments
	angleChanges := make([]float64, 0)
	for i := 2; i < len(events); i++ {
		angle1 := math.Atan2(float64(events[i-1].Y-events[i-2].Y), float64(events[i-1].X-events[i-2].X))
		angle2 := math.Atan2(float64(events[i].Y-events[i-1].Y), float64(events[i].X-events[i-1].X))
		change := math.Abs(angle2 - angle1)
		if change > math.Pi {
			change = 2*math.Pi - change
		}
		angleChanges = append(angleChanges, change)
	}

	if len(angleChanges) == 0 {
		return 0.5
	}

	// Higher variance = more random = more human
	variance := calculateVariance(angleChanges)
	// Normalized: typical human has variance around 0.5-1.5
	normalized := math.Min(variance/1.5, 1.0)
	return normalized
}

// calculateSpeedVariance calculates speed variance (higher = more human)
func calculateSpeedVariance(events []Event) float64 {
	if len(events) < 2 {
		return 0.5
	}

	speeds := make([]float64, 0)
	for i := 1; i < len(events); i++ {
		dx := float64(events[i].X - events[i-1].X)
		dy := float64(events[i].Y - events[i-1].Y)
		dt := float64(events[i].T - events[i-1].T)
		if dt > 0 {
			distance := math.Sqrt(dx*dx + dy*dy)
			speed := distance / dt
			speeds = append(speeds, speed)
		}
	}

	if len(speeds) < 2 {
		return 0.5
	}

	variance := calculateVariance(speeds)
	meanSpeed := mean(speeds)
	if meanSpeed == 0 {
		return 0.5
	}

	// Coefficient of variation (normalized variance)
	cv := variance / meanSpeed
	return math.Min(cv, 1.0)
}

// analyzeMouseTiming looks for unnatural timing patterns
func analyzeMouseTiming(events []Event) int {
	if len(events) < 2 {
		return 50
	}

	score := 100
	intervals := make([]float64, 0)
	for i := 1; i < len(events); i++ {
		interval := float64(events[i].T - events[i-1].T)
		if interval > 0 && interval < 2000 {
			intervals = append(intervals, interval)
		}
	}

	if len(intervals) < 2 {
		return 50
	}

	// Check for perfectly regular intervals (bot-like)
	variance := calculateVariance(intervals)
	if variance < 1 {
		score -= 50 // Suspiciously regular
	} else if variance < 10 {
		score -= 25
	}

	return score
}

func analyzeBehaviorVector(data BehaviorData) int {
	score := 100

	if data.MEntropy < 0.12 {
		score -= 28
	} else if data.MEntropy < 0.22 {
		score -= 14
	}

	if data.MMoves > 0 && data.MMoves < 4 && data.Clicks > 0 {
		score -= 16
	}

	if data.Clicks > 0 && data.MMoves == 0 {
		score -= 18
	}

	if data.Time > 0 {
		movesPerSecond := float64(data.MMoves) / float64(data.Time)
		if movesPerSecond > 14 {
			score -= 20
		}
	}

	if data.SDepth > 0 && data.SDepth < 3 && data.Time > 6 {
		score -= 8
	}

	if score < 0 {
		return 0
	}
	return score
}

func analyzeKeyboardVector(data BehaviorData) int {
	score := 100
	if data.KCount > 0 && data.KFlight > 0 {
		if data.KFlight < 35 {
			score -= 24
		} else if data.KFlight < 60 {
			score -= 12
		}
	}
	if data.KCount >= 6 && data.KFlight == 0 {
		score -= 28
	}
	if score < 0 {
		return 0
	}
	return score
}

func calculateMicroJitter(events []Event) float64 {
	if len(events) < 3 {
		return 0.1
	}

	var directionFlips float64
	for i := 2; i < len(events); i++ {
		prevDX := events[i-1].X - events[i-2].X
		prevDY := events[i-1].Y - events[i-2].Y
		nextDX := events[i].X - events[i-1].X
		nextDY := events[i].Y - events[i-1].Y
		if signChanged(prevDX, nextDX) || signChanged(prevDY, nextDY) {
			directionFlips++
		}
	}
	return directionFlips / float64(len(events)-2)
}

func calculateAccelerationVariance(events []Event) float64 {
	if len(events) < 3 {
		return 0.01
	}

	speeds := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		dx := float64(events[i].X - events[i-1].X)
		dy := float64(events[i].Y - events[i-1].Y)
		dt := float64(events[i].T - events[i-1].T)
		if dt <= 0 {
			continue
		}
		speeds = append(speeds, math.Sqrt(dx*dx+dy*dy)/dt)
	}
	if len(speeds) < 2 {
		return 0.01
	}

	accelerations := make([]float64, 0, len(speeds)-1)
	for i := 1; i < len(speeds); i++ {
		accelerations = append(accelerations, math.Abs(speeds[i]-speeds[i-1]))
	}
	return calculateVariance(accelerations)
}

func looksBezierLikeAutomation(events []Event) bool {
	if len(events) < 4 {
		return false
	}

	slopeChanges := 0
	for i := 2; i < len(events); i++ {
		a := events[i-2]
		b := events[i-1]
		c := events[i]
		abx := float64(b.X - a.X)
		aby := float64(b.Y - a.Y)
		bcx := float64(c.X - b.X)
		bcy := float64(c.Y - b.Y)
		cross := math.Abs(abx*bcy - aby*bcx)
		if cross > 2 {
			slopeChanges++
		}
	}
	return slopeChanges == 0
}

func signChanged(a, b int64) bool {
	return (a < 0 && b > 0) || (a > 0 && b < 0)
}

// Helper functions
func calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := mean(values)
	var sum float64
	for _, v := range values {
		sum += (v - m) * (v - m)
	}
	return sum / float64(len(values))
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
