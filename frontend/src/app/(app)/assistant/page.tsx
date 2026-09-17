"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { assistantApi, ApiError, isAiUnavailableError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { AiActionError, LoadingBlock } from "@/components/ui/misc";
import { Send } from "lucide-react";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export default function AssistantPage() {
  const toolsQuery = useQuery({ queryKey: ["assistant-tools"], queryFn: assistantApi.tools });
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [aiUnavailable, setAiUnavailable] = useState(false);

  const chatMutation = useMutation({
    mutationFn: (nextMessages: ChatMessage[]) => assistantApi.chat(nextMessages),
    onSuccess: (res) => {
      setMessages((m) => [...m, { role: "assistant", content: res.content }]);
      setError(null);
      setAiUnavailable(false);
    },
    onError: (err) => {
      setAiUnavailable(isAiUnavailableError(err));
      setError(err instanceof ApiError ? err.message : "Assistant unavailable");
    },
  });

  function send() {
    if (!input.trim()) return;
    const next = [...messages, { role: "user" as const, content: input }];
    setMessages(next);
    setInput("");
    chatMutation.mutate(next);
  }

  return (
    <div className="grid lg:grid-cols-[2fr_1fr] gap-6">
      <div className="space-y-4">
        <div>
          <h1 className="text-lg font-semibold">AI Assistant</h1>
          <p className="text-sm text-muted">Natural-language access to the same tools available in the UI — every risky action requires your approval.</p>
        </div>

        <Card className="h-[500px] flex flex-col">
          <CardContent className="flex-1 overflow-y-auto py-4 space-y-3">
            {messages.length === 0 && <p className="text-sm text-muted">Ask about compliance status, risk, or remediation for any scan.</p>}
            {messages.map((m, i) => (
              <div key={i} className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${m.role === "user" ? "ml-auto bg-primary/15" : "bg-surface-raised"}`}>
                {m.content}
              </div>
            ))}
            {chatMutation.isPending && <p className="text-xs text-muted">Thinking...</p>}
            {error && <AiActionError message={error} isAiUnavailable={aiUnavailable} />}
          </CardContent>
          <div className="border-t border-border p-3 flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && send()}
              placeholder="Ask a question..."
            />
            <Button size="sm" onClick={send} disabled={chatMutation.isPending}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </Card>
      </div>

      <div>
        <h2 className="text-sm font-semibold mb-3">Available Tools</h2>
        {toolsQuery.isLoading && <LoadingBlock />}
        <div className="space-y-2">
          {toolsQuery.data?.map((t) => (
            <Card key={t.name}>
              <CardHeader className="py-3">
                <CardTitle className="text-xs flex items-center justify-between">
                  <span>{t.name}</span>
                  <Badge className={t.requires_approval ? "text-warning border-warning/40" : "text-success border-success/40"}>
                    {t.risk_level}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="py-2 text-[11px] text-muted">{t.description}</CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
