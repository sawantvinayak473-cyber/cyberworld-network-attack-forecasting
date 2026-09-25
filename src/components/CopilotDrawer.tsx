import React, { useEffect, useRef, useState } from 'react';
import { Bot, Send, ShieldAlert, X } from 'lucide-react';
import { askCopilot, CopilotContext } from '../api/copilotApi';

interface CopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  context: Omit<CopilotContext, 'conversationHistory'>;
  prefilledQuestion?: string;
}

type ChatMessage = CopilotContext['conversationHistory'][number];

const SUGGESTED_QUESTIONS = [
  'Why is this critical?',
  'What happens next?',
  'Generate investigation plan',
  'Explain to management',
  'Which MITRE techniques?',
  'What evidence supports this?',
];

export const CopilotDrawer: React.FC<CopilotDrawerProps> = ({
  isOpen,
  onClose,
  context,
  prefilledQuestion = '',
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [question, setQuestion] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (isOpen && prefilledQuestion) {
      setQuestion(prefilledQuestion);
    }
  }, [isOpen, prefilledQuestion]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isLoading]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isOpen) onClose();
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  const sendQuestion = async (value = question) => {
    const trimmedQuestion = value.trim();
    if (!trimmedQuestion || isLoading) return;

    const userMessage: ChatMessage = { role: 'user', content: trimmedQuestion };
    setMessages((previous) => [...previous, userMessage]);
    setQuestion('');
    setHasError(false);
    setIsLoading(true);

    try {
      const answer = await askCopilot(trimmedQuestion, {
        ...context,
        conversationHistory: messages,
      });
      setMessages((previous) => [...previous, { role: 'assistant', content: answer }]);
    } catch {
      setHasError(true);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <aside
      className={`fixed inset-y-0 right-0 z-[70] flex w-full max-w-[400px] flex-col border-l border-slate-700 bg-[#090d16] shadow-2xl shadow-black/60 transition-transform duration-300 ease-out sm:w-[400px] ${
        isOpen ? 'translate-x-0' : 'translate-x-full pointer-events-none'
      }`}
      aria-hidden={!isOpen}
      aria-label="CyberWorld SOC Copilot"
    >
      <header className="flex items-center justify-between border-b border-slate-800 px-4 py-3.5">
        <div className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-700/60 bg-emerald-950/45">
            <ShieldAlert className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="font-mono text-sm font-bold tracking-wide text-slate-100">AI SOC COPILOT</h2>
            <p className="text-[10px] font-mono text-emerald-400">CONTEXT-BOUND ANALYST ASSISTANCE</p>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-slate-700 bg-slate-900 p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          aria-label="Close Copilot"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
          {messages.length === 0 && !isLoading && (
            <div className="flex min-h-[220px] flex-col items-center justify-center px-5 text-center">
              <Bot className="mb-3 h-8 w-8 text-emerald-400" />
              <p className="font-mono text-sm text-slate-300">Ready for an incident question.</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">
                Answers are limited to the active CyberWorld telemetry context.
              </p>
            </div>
          )}

          {messages.map((message, index) => (
            <div
              key={`${message.role}-${index}-${message.content.slice(0, 16)}`}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-xl px-3 py-2.5 text-sm leading-5 shadow-sm ${
                  message.role === 'user'
                    ? 'rounded-br-sm bg-emerald-600 text-white'
                    : 'rounded-bl-sm bg-slate-800 text-slate-200'
                }`}
              >
                <p className="whitespace-pre-wrap break-words">{message.content}</p>
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="flex justify-start" aria-live="polite" aria-label="Copilot is thinking">
              <div className="flex items-center gap-1.5 rounded-xl rounded-bl-sm bg-slate-800 px-4 py-3">
                {[0, 1, 2].map((dot) => (
                  <span
                    key={dot}
                    className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400"
                    style={{ animationDelay: `${dot * 160}ms` }}
                  />
                ))}
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <div className="border-t border-slate-800 bg-slate-950/40 p-3.5">
          {hasError && (
            <p className="mb-3 text-xs font-mono text-amber-400" role="alert">
              Copilot unavailable — check API key in .env
            </p>
          )}
          <div className="mb-3 flex flex-wrap gap-1.5">
            {SUGGESTED_QUESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => void sendQuestion(suggestion)}
                disabled={isLoading}
                className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[10px] font-mono text-slate-300 transition-colors hover:border-emerald-600/70 hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {suggestion}
              </button>
            ))}
          </div>
          <form
            className="flex items-center gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              void sendQuestion();
            }}
          >
            <input
              ref={inputRef}
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Ask about this incident…"
              disabled={isLoading}
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none disabled:opacity-60"
              aria-label="Ask the SOC Copilot"
            />
            <button
              type="submit"
              disabled={!question.trim() || isLoading}
              className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white transition-colors hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-500"
              aria-label="Send question"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
        </div>
      </div>
    </aside>
  );
};
