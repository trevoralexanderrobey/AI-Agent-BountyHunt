async function summarizeResearch({ research_text }) {
  // Minimal starter: produce a short structured summary based on input text.
  // Extend this to parse PDF text, extract indicators, and call local models.
  if (!research_text || research_text.trim().length === 0) {
    return { summary: 'No research text provided.' }
  }

  // Heuristic split and extract top points.
  const sentences = research_text.split(/(?<=[.?!])\s+/).filter(Boolean)
  const top = sentences.slice(0, 6).join(' ')

  const suggested_actions = [
    'Review identified IOCs and triage for false positives',
    'Map any disclosed exploit chains to known CVEs',
    'Prioritize targets by exposed attack surface',
  ]

  const summary = `Top excerpts: ${top}\n\nSuggested actions: ${suggested_actions.join('; ')}`
  return { summary }
}

module.exports = { summarizeResearch }
