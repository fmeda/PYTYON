# chatbot_security.py

import random

class SecurityChatbot:
    def __init__(self):
        self.responses = {
            "default": "Desculpe, não entendi sua pergunta.",
            "phishing": "Phishing é um tipo de ataque onde o criminoso tenta se passar por uma entidade confiável.",
        }

    def respond(self, user_input):
        if "phishing" in user_input.lower():
            return self.responses["phishing"]
        return self.responses["default"]
