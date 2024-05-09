import speech_recognition as speech #type:ignore
import pyttsx3 #type:ignore
import pywhatkit #type:ignore
import datetime
import wikipedia #type:ignore
import pyjokes #type:ignore
listener = speech.Recognizer()
engine = pyttsx3.init()
voices = engine.getProperty('voices')
engine.setProperty('voice', voices[1].id)


def talk(text):
    engine.say(text)
    engine.runAndWait()


def take_command():
    try:
        with speech.Microphone() as source:
            print('listening...')
            voice = listener.listen(source)
            command = listener.recognize_google_cloud(voice)
            command = command.lower()
            if 'yami' in command:
                command = command.replace('yami', '')
                print(command)
    except:
        pass
    return command

def run_yami():
    command = take_command()
    print(command)
    if 'play' in command:
        song = command.replace('play', '')
        talk('playing ' + song)
        pywhatkit.playonyt(song)
    elif 'time' in command:
        time = datetime.datetime.now().strftime('%I:%M %p')
        talk('Current time is ' + time)
    elif 'who is it' in command:
        person = command.replace('who is it', '')
        info = wikipedia.summary(person, 1)
        print(info)
        talk(info)
    elif 'date' in command:
        talk('sorry, I have a headache')
    elif 'are you single' in command:
        talk('I am in a relationship with wifi')
    elif 'joke' in command:
        talk(pyjokes.get_joke())
    else:
        talk('Please say the command again.')


while True:
    run_yami()  