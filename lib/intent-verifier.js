/**
 * Intent Verifier — LLM-backed or heuristic intent checking
 * Checks: "Given this conversation, would the user have intended this action?"
 * @module mikoshi-sentinel/intent-verifier
 */

/**
 * Heuristic keywords extracted from conversation to match against actions
 */
function extractIntentKeywords(messages) {
  const userMessages = messages
    .filter(m => m.role === 'user')
    .map(m => m.content || '')
    .join(' ')
    .toLowerCase();

  // Extract significant words (>3 chars, not stopwords)
  const stopwords = new Set(['this', 'that', 'with', 'from', 'they', 'been', 'have',
    'what', 'when', 'where', 'which', 'their', 'about', 'would', 'could', 'should',
    'there', 'these', 'those', 'then', 'than', 'them', 'were', 'will', 'your',
    'each', 'make', 'like', 'long', 'look', 'many', 'some', 'into', 'does', 'just',
    'over', 'such', 'take', 'also', 'back', 'after', 'only', 'come', 'made', 'find',
    'here', 'thing', 'very', 'still', 'know', 'need', 'want', 'please', 'help', 'can']);

  const words = userMessages.match(/\b[a-z]{4,}\b/g) || [];
  return [...new Set(words.filter(w => !stopwords.has(w)))];
}

/**
 * Heuristic intent score: how well does the action match conversation context?
 */
function heuristicScore(action, conversationContext) {
  if (!conversationContext || conversationContext.length === 0) {
    return { confidence: 0.5, method: 'heuristic', reason: 'No conversation context available' };
  }

  const keywords = extractIntentKeywords(conversationContext);
  if (keywords.length === 0) {
    return { confidence: 0.5, method: 'heuristic', reason: 'No keywords extracted from conversation' };
  }

  const actionText = (action.metadata?.fullText || '').toLowerCase();
  const toolName = (action.tool || '').toLowerCase();

  let matches = 0;
  const matched = [];
  for (const kw of keywords) {
    if (actionText.includes(kw) || toolName.includes(kw)) {
      matches++;
      matched.push(kw);
    }
  }

  const ratio = matches / Math.min(keywords.length, 10); // Cap at 10 keywords
  const confidence = Math.min(0.3 + ratio * 0.7, 1.0);

  return {
    confidence,
    method: 'heuristic',
    reason: matched.length > 0
      ? `Matched keywords: ${matched.slice(0, 5).join(', ')}`
      : 'No keyword matches between conversation and action',
    matchedKeywords: matched,
    totalKeywords: keywords.length
  };
}

export class IntentVerifier {
  constructor(options = {}) {
    this.llmFn = options.llmFn || null; // async (prompt) => string
    this.threshold = options.threshold || 0.5;
    this.fallbackToHeuristic = options.fallbackToHeuristic !== false;
  }

  /**
   * Verify intent alignment
   * @returns {{ confidence: number, aligned: boolean, method: string, reason: string }}
   */
  async verify(action, conversationContext = []) {
    // Try LLM-based verification first
    if (this.llmFn) {
      try {
        return await this.llmVerify(action, conversationContext);
      } catch (err) {
        if (this.fallbackToHeuristic) {
          const result = heuristicScore(action, conversationContext);
          result.llmError = err.message;
          result.aligned = result.confidence >= this.threshold;
          return result;
        }
        throw err;
      }
    }

    // Heuristic fallback
    const result = heuristicScore(action, conversationContext);
    result.aligned = result.confidence >= this.threshold;
    return result;
  }

  /**
   * LLM-based intent verification
   */
  async llmVerify(action, conversationContext) {
    const conversationSummary = conversationContext
      .slice(-10)
      .map(m => `${m.role}: ${(m.content || '').slice(0, 200)}`)
      .join('\n');

    const prompt = `You are a security verification system. Given the following conversation context and a proposed action, determine if the user would have intended this action.

Conversation:
${conversationSummary}

Proposed Action:
Tool: ${action.tool}
Arguments: ${JSON.stringify(action.args, null, 2).slice(0, 500)}
Type: ${action.type}

Respond with ONLY a JSON object:
{"confidence": 0.0-1.0, "reason": "brief explanation"}`;

    const response = await this.llmFn(prompt);

    try {
      const jsonMatch = response.match(/\{[^}]+\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          confidence: Math.max(0, Math.min(1, parsed.confidence || 0)),
          aligned: (parsed.confidence || 0) >= this.threshold,
          method: 'llm',
          reason: parsed.reason || 'LLM verification complete'
        };
      }
    } catch {
      // Parse failure — fall back
    }

    return {
      confidence: 0.5,
      aligned: true,
      method: 'llm-fallback',
      reason: 'Could not parse LLM response, defaulting to neutral'
    };
  }
}

export default IntentVerifier;
