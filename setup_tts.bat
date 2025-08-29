@echo off
echo Installing Amazon Interview TTS Helper dependencies...
echo.

pip install pyttsx3 gtts pygame edge-tts

echo.
echo Installation complete!
echo.
echo Usage:
echo   python tts_interview_helper.py --tts local     (Offline, immediate)
echo   python tts_interview_helper.py --tts google    (Online, high quality)  
echo   python tts_interview_helper.py --tts edge      (Online, neural voices)
echo.
pause