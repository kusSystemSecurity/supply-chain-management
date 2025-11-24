import { useState, useRef, useEffect } from "react"
import { X, Send, Loader2, Bot, User } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import axios from "axios"
import { cn } from "@/lib/utils"

interface Message {
    role: "user" | "assistant"
    content: string
}

export function Chatbot() {
    const [isOpen, setIsOpen] = useState(false)
    const [messages, setMessages] = useState<Message[]>([
        { role: "assistant", content: "Hello! I'm your SecureChain AI assistant. How can I help you today?" }
    ])
    const [input, setInput] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const scrollAreaRef = useRef<HTMLDivElement>(null)

    useEffect(() => {
        if (scrollAreaRef.current) {
            scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight
        }
    }, [messages, isOpen])

    const handleSend = async () => {
        if (!input.trim() || isLoading) return

        const userMessage = input.trim()
        setInput("")
        setMessages(prev => [...prev, { role: "user", content: userMessage }])
        setIsLoading(true)

        try {
            // In a real app, we might want to pass history context
            // For now, the backend is stateless per request but we could send history if needed
            const response = await axios.post("http://localhost:8000/api/chat", {
                message: userMessage,
                history: messages.map(m => ({ role: m.role, content: m.content }))
            })

            setMessages(prev => [...prev, { role: "assistant", content: response.data.response }])
        } catch (error) {
            console.error("Chat error:", error)
            setMessages(prev => [...prev, { role: "assistant", content: "Sorry, I encountered an error processing your request." }])
        } finally {
            setIsLoading(false)
        }
    }

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault()
            handleSend()
        }
    }

    return (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col items-end">
            {isOpen && (
                <Card className="w-[400px] h-[500px] mb-4 shadow-xl flex flex-col animate-in slide-in-from-bottom-10 fade-in duration-300">
                    <CardHeader className="p-4 border-b flex flex-row items-center justify-between space-y-0 bg-primary text-primary-foreground rounded-t-lg">
                        <div className="flex items-center gap-2">
                            <Bot className="h-5 w-5" />
                            <CardTitle className="text-base">SecureChain Assistant</CardTitle>
                        </div>
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-primary-foreground hover:bg-primary/90" onClick={() => setIsOpen(false)}>
                            <X className="h-4 w-4" />
                        </Button>
                    </CardHeader>
                    <CardContent className="flex-1 p-0 overflow-hidden">
                        <ScrollArea className="h-full p-4" ref={scrollAreaRef}>
                            <div className="flex flex-col gap-4">
                                {messages.map((msg, index) => (
                                    <div
                                        key={index}
                                        className={cn(
                                            "flex gap-2 max-w-[85%]",
                                            msg.role === "user" ? "ml-auto flex-row-reverse" : "mr-auto"
                                        )}
                                    >
                                        <div className={cn(
                                            "h-8 w-8 rounded-full flex items-center justify-center shrink-0",
                                            msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted"
                                        )}>
                                            {msg.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                                        </div>
                                        <div className={cn(
                                            "rounded-lg p-3 text-sm",
                                            msg.role === "user"
                                                ? "bg-primary text-primary-foreground"
                                                : "bg-muted text-foreground"
                                        )}>
                                            <ReactMarkdown
                                                remarkPlugins={[remarkGfm]}
                                            >
                                                {msg.content}
                                            </ReactMarkdown>
                                        </div>
                                    </div>
                                ))}
                                {isLoading && (
                                    <div className="flex gap-2 mr-auto max-w-[85%]">
                                        <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center shrink-0">
                                            <Bot className="h-4 w-4" />
                                        </div>
                                        <div className="bg-muted rounded-lg p-3 flex items-center">
                                            <Loader2 className="h-4 w-4 animate-spin" />
                                        </div>
                                    </div>
                                )}
                            </div>
                        </ScrollArea>
                    </CardContent>
                    <CardFooter className="p-3 border-t bg-background">
                        <div className="flex w-full items-center gap-2">
                            <Input
                                placeholder="Ask about scans, vulnerabilities..."
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={handleKeyDown}
                                disabled={isLoading}
                                className="flex-1"
                            />
                            <Button size="icon" onClick={handleSend} disabled={isLoading || !input.trim()}>
                                <Send className="h-4 w-4" />
                            </Button>
                        </div>
                    </CardFooter>
                </Card>
            )}

            <Button
                size="icon"
                className="h-14 w-14 rounded-full shadow-lg"
                onClick={() => setIsOpen(!isOpen)}
            >
                {isOpen ? <X className="h-6 w-6" /> : <Bot className="h-6 w-6" />}
            </Button>
        </div>
    )
}
