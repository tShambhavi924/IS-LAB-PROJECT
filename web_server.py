from flask import Flask, render_template_string
import webbrowser
import threading

app = Flask(__name__)

with open('dashboard.html', 'r', encoding='utf-8') as f:
    DASHBOARD_HTML = f.read()
 
@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

def open_browser():
    webbrowser.open('http://localhost:8080')

if __name__ == '__main__':
    
    threading.Timer(1, open_browser).start()
    
    print("="*60)
    print(" Network Security Dashboard Starting...")
    print("="*60)
    print("\n Dashboard URL: http://localhost:8080")
    print("Opening browser automatically...\n")
    print("Press Ctrl+C to stop\n")
    
    app.run(debug=False, port=8080)