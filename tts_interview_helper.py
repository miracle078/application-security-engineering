#!/usr/bin/env python3
"""
Amazon Interview Preparation - Text-to-Speech Helper
Interactive interview practice with audio feedback using multiple TTS options
"""

import os
import json
import requests
import pygame
import io
import tempfile
from pathlib import Path
import argparse
import sys

try:
    import pyttsx3
    PYTTSX3_AVAILABLE = True
except ImportError:
    PYTTSX3_AVAILABLE = False
    print("pyttsx3 not installed. Install with: pip install pyttsx3")

try:
    from gtts import gTTS
    GTTS_AVAILABLE = True
except ImportError:
    GTTS_AVAILABLE = False
    print("gTTS not installed. Install with: pip install gtts")

class InterviewTTSHelper:
    """Text-to-Speech helper for Amazon interview preparation"""
    
    def __init__(self, tts_method='local'):
        self.tts_method = tts_method
        self.temp_dir = Path(tempfile.gettempdir()) / "interview_tts"
        self.temp_dir.mkdir(exist_ok=True)
        
        # Initialize pygame for audio playback
        try:
            pygame.mixer.init()
            self.pygame_available = True
        except:
            self.pygame_available = False
            print("pygame not available for audio playback")
        
        # Initialize local TTS engine
        if PYTTSX3_AVAILABLE and tts_method == 'local':
            self.tts_engine = pyttsx3.init()
            self.setup_local_voice()
    
    def setup_local_voice(self):
        """Configure local TTS voice settings"""
        voices = self.tts_engine.getProperty('voices')
        # Try to find a clear voice (prefer Microsoft voices on Windows)
        preferred_voices = ['Microsoft Zira', 'Microsoft David', 'Microsoft Mark']
        
        selected_voice = None
        for voice in voices:
            for preferred in preferred_voices:
                if preferred.lower() in voice.name.lower():
                    selected_voice = voice.id
                    break
            if selected_voice:
                break
        
        if selected_voice:
            self.tts_engine.setProperty('voice', selected_voice)
        
        # Set speech rate (words per minute)
        self.tts_engine.setProperty('rate', 160)  # Slightly slower for clarity
        self.tts_engine.setProperty('volume', 0.9)
    
    def speak_local(self, text):
        """Use local pyttsx3 for immediate speech"""
        if not PYTTSX3_AVAILABLE:
            print("Local TTS not available")
            return False
        
        try:
            self.tts_engine.say(text)
            self.tts_engine.runAndWait()
            return True
        except Exception as e:
            print(f"Local TTS error: {e}")
            return False
    
    def speak_google(self, text, lang='en', slow=False):
        """Use Google TTS (requires internet)"""
        if not GTTS_AVAILABLE:
            print("Google TTS not available")
            return False
        
        try:
            # Create TTS object
            tts = gTTS(text=text, lang=lang, slow=slow)
            
            # Save to temporary file
            temp_file = self.temp_dir / f"tts_temp_{hash(text)}.mp3"
            tts.save(str(temp_file))
            
            # Play the audio file
            if self.pygame_available:
                pygame.mixer.music.load(str(temp_file))
                pygame.mixer.music.play()
                
                # Wait for playback to complete
                while pygame.mixer.music.get_busy():
                    pygame.time.wait(100)
                
                # Clean up
                temp_file.unlink()
                return True
            else:
                print(f"Audio saved to: {temp_file}")
                return True
                
        except Exception as e:
            print(f"Google TTS error: {e}")
            return False
    
    def speak_edge_tts(self, text, voice='en-US-AriaNeural'):
        """Use Microsoft Edge TTS (free, no API key needed)"""
        try:
            import edge_tts
            import asyncio
            
            async def create_speech():
                communicate = edge_tts.Communicate(text, voice)
                temp_file = self.temp_dir / f"edge_tts_{hash(text)}.mp3"
                await communicate.save(str(temp_file))
                return temp_file
            
            # Run async function
            temp_file = asyncio.run(create_speech())
            
            # Play the audio
            if self.pygame_available:
                pygame.mixer.music.load(str(temp_file))
                pygame.mixer.music.play()
                
                while pygame.mixer.music.get_busy():
                    pygame.time.wait(100)
                
                temp_file.unlink()
                return True
            else:
                print(f"Audio saved to: {temp_file}")
                return True
                
        except ImportError:
            print("edge-tts not installed. Install with: pip install edge-tts")
            return False
        except Exception as e:
            print(f"Edge TTS error: {e}")
            return False
    
    def speak(self, text):
        """Main speak function - tries available methods"""
        print(f"\n🔊 Speaking: {text[:100]}{'...' if len(text) > 100 else ''}")
        
        # Try the configured method first
        if self.tts_method == 'local':
            if self.speak_local(text):
                return True
        elif self.tts_method == 'google':
            if self.speak_google(text):
                return True
        elif self.tts_method == 'edge':
            if self.speak_edge_tts(text):
                return True
        
        # Fallback to other methods
        methods = [
            ('local', self.speak_local),
            ('google', self.speak_google),
            ('edge', self.speak_edge_tts)
        ]
        
        for method_name, method_func in methods:
            if method_name != self.tts_method:
                print(f"Trying {method_name} TTS...")
                if method_func(text):
                    return True
        
        # Ultimate fallback - just print
        print(f"TTS failed, displaying text: {text}")
        return False
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            for file in self.temp_dir.glob("*.mp3"):
                file.unlink()
            if self.temp_dir.exists() and not list(self.temp_dir.iterdir()):
                self.temp_dir.rmdir()
        except Exception as e:
            print(f"Cleanup error: {e}")

class InteractiveInterviewPractice:
    """Interactive Amazon interview practice with TTS"""
    
    def __init__(self, tts_method='local'):
        self.tts = InterviewTTSHelper(tts_method)
        self.interview_content = self.load_interview_content()
    
    def load_interview_content(self):
        """Load interview questions and content"""
        return {
            "technical_questions": [
                {
                    "question": "Walk me through how you would threat model a file upload feature for Amazon's retail website that handles millions of uploads daily.",
                    "key_points": ["STRIDE methodology", "Scale considerations", "Customer impact", "AWS integration"],
                    "time_limit": "15 minutes"
                },
                {
                    "question": "How would you handle a critical SQL injection vulnerability discovered in production affecting customer payment data?",
                    "key_points": ["Immediate containment", "Impact assessment", "Remediation plan", "Prevention measures"],
                    "time_limit": "10 minutes"
                },
                {
                    "question": "Design a security automation system that can audit IAM permissions across 500 AWS accounts.",
                    "key_points": ["Cross-account access", "Scalability", "Reporting", "Cost efficiency"],
                    "time_limit": "12 minutes"
                }
            ],
            "leadership_principles": [
                {
                    "principle": "Customer Obsession",
                    "question": "Tell me about a time when you had to balance security requirements with customer experience.",
                    "focus": "Customer impact and trust metrics"
                },
                {
                    "principle": "Ownership",
                    "question": "Describe a security project you owned from start to finish.",
                    "focus": "Personal accountability and long-term thinking"
                },
                {
                    "principle": "Invent and Simplify",
                    "question": "Tell me about a time you created a new security solution or simplified a complex security process.",
                    "focus": "Innovation and developer enablement"
                }
            ],
            "business_scenarios": [
                {
                    "scenario": "Calculate the business impact of a data breach affecting 100,000 Prime members",
                    "framework": "CLV protection + regulatory costs + trust impact"
                }
            ]
        }
    
    def run_technical_practice(self):
        """Practice technical questions with TTS"""
        self.tts.speak("Let's practice technical interview questions. I'll ask you a question, give you time to think, then we'll discuss the key points.")
        
        for i, q in enumerate(self.interview_content["technical_questions"], 1):
            self.tts.speak(f"Technical Question {i}")
            self.tts.speak(q["question"])
            self.tts.speak(f"You have {q['time_limit']} to respond. Think through your systematic approach.")
            
            input("\nPress Enter when you're ready to hear the key points to cover...")
            
            self.tts.speak("Here are the key points you should have covered:")
            for point in q["key_points"]:
                self.tts.speak(point)
            
            feedback = input("\nHow did you do? Rate yourself 1-5 and press Enter to continue...")
            self.tts.speak(f"You rated yourself {feedback}. Let's move to the next question.")
    
    def run_leadership_practice(self):
        """Practice Leadership Principles with TTS"""
        self.tts.speak("Now let's practice Leadership Principles using the STAR method.")
        
        for lp in self.interview_content["leadership_principles"]:
            self.tts.speak(f"Leadership Principle: {lp['principle']}")
            self.tts.speak(lp["question"])
            self.tts.speak(f"Focus on: {lp['focus']}")
            self.tts.speak("Structure your response using STAR: Situation, Task, Action, Result. Include specific metrics.")
            
            input("\nPress Enter when ready for feedback...")
            
            self.tts.speak("Remember to include: Specific business context, Personal accountability using 'I' statements, Quantified outcomes, Customer impact connection")
    
    def run_business_calculations(self):
        """Practice business impact calculations"""
        self.tts.speak("Let's practice business impact calculations that are crucial for Amazon interviews.")
        
        for scenario in self.interview_content["business_scenarios"]:
            self.tts.speak(f"Scenario: {scenario['scenario']}")
            self.tts.speak(f"Use this framework: {scenario['framework']}")
            
            input("\nCalculate the impact and press Enter for the solution...")
            
            self.tts.speak("Solution: 100,000 Prime members times $2,500 CLV equals $250 million base impact. Multiply by 2.5 for breach multiplier equals $625 million total business impact. Add GDPR notification costs of $16.5 million. Total impact: approximately $642 million.")
    
    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            menu_text = """
Amazon Interview Practice Menu:
1. Technical Questions (30 minutes)
2. Leadership Principles (30 minutes) 
3. Business Impact Calculations (15 minutes)
4. Full Phone Screen Simulation (60 minutes)
5. Exit

Choose an option (1-5):"""
            
            print(menu_text)
            self.tts.speak("Choose your practice option: Technical Questions, Leadership Principles, Business Calculations, Full Simulation, or Exit")
            
            choice = input().strip()
            
            if choice == '1':
                self.run_technical_practice()
            elif choice == '2':
                self.run_leadership_practice()
            elif choice == '3':
                self.run_business_calculations()
            elif choice == '4':
                self.tts.speak("Starting full 60-minute phone screen simulation")
                self.run_technical_practice()
                self.run_leadership_practice()
                self.tts.speak("Phone screen simulation complete. Great job!")
            elif choice == '5':
                self.tts.speak("Good luck with your Amazon interview! Remember: Customer obsession, quantified impact, and systematic thinking.")
                break
            else:
                self.tts.speak("Please choose a valid option from 1 to 5")

def main():
    parser = argparse.ArgumentParser(description='Amazon Interview TTS Practice Helper')
    parser.add_argument('--tts', choices=['local', 'google', 'edge'], default='local',
                      help='TTS method to use (default: local)')
    parser.add_argument('--install-deps', action='store_true',
                      help='Show installation instructions for dependencies')
    
    args = parser.parse_args()
    
    if args.install_deps:
        print("""
Installation Instructions:

1. Required packages:
   pip install pyttsx3 gtts pygame

2. Optional (for Edge TTS):
   pip install edge-tts

3. For Windows users, pyttsx3 works best with system voices
4. For cross-platform, Google TTS requires internet connection
5. Edge TTS offers high-quality voices without API keys

Run the script again without --install-deps to start practicing!
        """)
        return
    
    try:
        practice = InteractiveInterviewPractice(args.tts)
        practice.tts.speak("Welcome to Amazon Interview Practice with Text-to-Speech! Let's prepare for your Application Security Engineer interview.")
        practice.interactive_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if 'practice' in locals():
            practice.tts.cleanup()

if __name__ == "__main__":
    main()