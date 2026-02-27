/**
 * useVoiceInput.js – Phase 5
 * Wraps the browser Web Speech API for hands-free chat input.
 * Works in Chrome, Edge, and other Chromium-based browsers.
 * Gracefully degrades when the API is not available.
 *
 * Usage:
 *   const { isListening, transcript, startListening, stopListening, supported } = useVoiceInput(onResult);
 *   onResult(text) is called when final speech is recognized.
 */

import { useState, useRef, useCallback } from 'react';

const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

function useVoiceInput(onResult) {
    const [isListening, setIsListening] = useState(false);
    const [transcript, setTranscript] = useState('');
    const [error, setError] = useState(null);
    const recognitionRef = useRef(null);
    const supported = Boolean(SpeechRecognition);

    const startListening = useCallback(() => {
        if (!supported || isListening) return;

        setError(null);
        setTranscript('');

        const recognition = new SpeechRecognition();
        recognitionRef.current = recognition;

        recognition.lang = 'en-US';
        recognition.continuous = false;       // one phrase at a time
        recognition.interimResults = true;    // show partial transcripts
        recognition.maxAlternatives = 1;

        recognition.onstart = () => setIsListening(true);

        recognition.onresult = (event) => {
            let interim = '';
            let final = '';

            for (let i = event.resultIndex; i < event.results.length; i++) {
                const result = event.results[i];
                if (result.isFinal) {
                    final += result[0].transcript;
                } else {
                    interim += result[0].transcript;
                }
            }

            setTranscript(final || interim);

            // Auto-submit final transcript to caller
            if (final.trim()) {
                onResult?.(final.trim());
            }
        };

        recognition.onerror = (event) => {
            setError(event.error);
            setIsListening(false);
        };

        recognition.onend = () => {
            setIsListening(false);
            setTranscript('');
        };

        recognition.start();
    }, [supported, isListening, onResult]);

    const stopListening = useCallback(() => {
        recognitionRef.current?.stop();
        setIsListening(false);
    }, []);

    return {
        supported,
        isListening,
        transcript,
        error,
        startListening,
        stopListening,
    };
}

export default useVoiceInput;
