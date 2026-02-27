/**
 * useTTS.js – Phase 5
 * Text-to-Speech hook using the browser's speechSynthesis API.
 * Strips markdown, code blocks, and special symbols before speaking.
 *
 * Usage:
 *   const { speak, stop, isSpeaking } = useTTS();
 */

import { useState, useCallback, useRef } from 'react';

// Strip markdown and code artefacts that would sound terrible when spoken
function cleanText(text) {
    return text
        .replace(/```[\s\S]*?```/g, 'code block omitted')   // code blocks
        .replace(/`[^`]+`/g, '')                             // inline code
        .replace(/\*\*(.*?)\*\*/g, '$1')                     // bold
        .replace(/\*(.*?)\*/g, '$1')                         // italics
        .replace(/#+\s/g, '')                                // headings
        .replace(/⚠️|🛡️|🔍|🤖|🔴|🟡|🟠|⛔|🔵/g, '')      // emojis
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')            // links
        .replace(/[-*]\s/g, '')                              // list bullets
        .replace(/\s{2,}/g, ' ')                             // extra spaces
        .trim();
}

function useTTS() {
    const [isSpeaking, setIsSpeaking] = useState(false);
    const utteranceRef = useRef(null);
    const supported = Boolean(window.speechSynthesis);

    const speak = useCallback((text) => {
        if (!supported || !text) return;

        // Cancel current speech first
        window.speechSynthesis.cancel();

        const cleaned = cleanText(text);
        if (!cleaned) return;

        const utterance = new SpeechSynthesisUtterance(cleaned);
        utteranceRef.current = utterance;

        // Prefer a natural-sounding voice
        const voices = window.speechSynthesis.getVoices();
        const preferred = voices.find(v =>
            v.lang.startsWith('en') && (v.name.includes('Google') || v.name.includes('Samantha') || v.name.includes('Daniel'))
        ) || voices.find(v => v.lang.startsWith('en'));
        if (preferred) utterance.voice = preferred;

        utterance.rate = 1.0;
        utterance.pitch = 1.0;
        utterance.volume = 0.9;

        utterance.onstart = () => setIsSpeaking(true);
        utterance.onend = () => setIsSpeaking(false);
        utterance.onerror = () => setIsSpeaking(false);

        window.speechSynthesis.speak(utterance);
    }, [supported]);

    const stop = useCallback(() => {
        window.speechSynthesis.cancel();
        setIsSpeaking(false);
    }, []);

    return { speak, stop, isSpeaking, supported };
}

export default useTTS;
