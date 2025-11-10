from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from hash_utils import comp_sha256, save_hash_to_file, load_hash_from_file, verify_integrity, gen_fingerprint
import bcrypt
import os
import time
from Crypto.PublicKey import RSA
from werkzeug.utils import secure_filename
from crypto_utils import (
    generate_rsa_keypair,
    handle_upload_and_encrypt,
    handle_decrypt_and_verify,
    list_encrypted_files,
    KEYS_DIR,
)


app = Flask(__name__)
app.secret_key = "supersecretkey"  # replace in production

# Database setup (SQLite)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)

with app.app_context():
    db.create_all()

# --- Helper/demo functions ---
def demo_hashes_web(password: str):
    h1 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    h2 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return h1.decode('utf-8'), h2.decode('utf-8')

def brute_force_time(password: str, rounds: int = 12):
    start = time.time()
    _ = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=rounds))
    return time.time() - start

def parse_bcrypt_hash(hash_text: str):
    out = {}
    if not hash_text or not hash_text.startswith("$2"):
        out["error"] = "Not a valid bcrypt hash (must start with $2...)."
        return out
    parts = hash_text.split("$")
    if len(parts) < 4:
        out["error"] = "Unexpected bcrypt format (too few $ parts)."
        return out
    out["algorithm"] = parts[1]
    out["cost"] = parts[2]
    rest = parts[3]
    out["salt_and_hash"] = rest
    if len(rest) >= 53:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:22+31]
    else:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:] if len(rest) > 22 else ""
    return out

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

# registration/login/dashboard/logout unchanged (kept for brevity)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Please enter username and password.", "error")
            return redirect(url_for('register'))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists.", "error")
            return redirect(url_for('register'))

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful — please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Please enter username and password.", "error")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            session['username'] = username
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect password.", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have logged out.", "success")
    return redirect(url_for('home'))

# --- Demo routes (robust) ---
@app.route('/demo_hashes', methods=['GET', 'POST'])
def demo_hashes():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        print("DEBUG demo_hashes POST received, password present?", bool(password))
        if password == '':
            flash("Enter a password to demo.", "error")
            return redirect(url_for('demo_hashes'))
        h1, h2 = demo_hashes_web(password)
        result = {'h1': h1, 'h2': h2}
        print("DEBUG demo_hashes produced:", result['h1'][:20], "...")
    return render_template('demo_hashes.html', result=result)

@app.route('/demo_bruteforce', methods=['GET', 'POST'])
def demo_bruteforce():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        rounds_raw = request.form.get('rounds', '')
        try:
            rounds = int(rounds_raw) if rounds_raw else 12
        except ValueError:
            rounds = 12
        print("DEBUG demo_bruteforce POST received: rounds=", rounds, "password present?", bool(password))
        if password == '':
            flash("Enter a password to time.", "error")
            return redirect(url_for('demo_bruteforce'))
        secs = brute_force_time(password, rounds=rounds)
        result = {'rounds': rounds, 'seconds': secs}
        print("DEBUG brute force time:", secs)
    return render_template('demo_bruteforce.html', result=result)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    parsed = None
    if request.method == 'POST':
        h = request.form.get('hashtext', '').strip()
        print("DEBUG analyze received:", bool(h))
        if not h:
            flash("Please paste a bcrypt hash to analyze.", "error")
            return redirect(url_for('analyze'))
        parsed = parse_bcrypt_hash(h)
        print("DEBUG analyze parsed:", parsed.get('error') if parsed.get('error') else "ok")
    return render_template('analyze.html', parsed=parsed)

# Route to generate RSA keypair (one-time, protected in real app)
@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if 'username' not in session:
        flash("Please log in to generate keys.", "error")
        return redirect(url_for('login'))

    try:
        os.makedirs('keys', exist_ok=True)

        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save to files
        with open("keys/rsa_private.pem", "wb") as priv_file:
            priv_file.write(private_key)
        with open("keys/rsa_public.pem", "wb") as pub_file:
            pub_file.write(public_key)

        flash("RSA keypair generated successfully!", "success")
    except Exception as e:
        flash(f"Could not generate keys: {e}", "error")

    # Redirect back to the homepage (not dashboard)
    return redirect(url_for('home'))
# Upload + encrypt route (available to logged-in users)
@app.route('/upload_encrypt', methods=['GET', 'POST'])
def upload_encrypt():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part.", "error")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash("No selected file.", "error")
            return redirect(request.url)

        safe_name = secure_filename(file.filename)
        meta = handle_upload_and_encrypt(file, filename=safe_name)
        # You could store meta in DB for the user (filename, paths, fingerprint, etc.)
        flash(f"File encrypted and saved as {meta['encrypted_filename']}. SHA-256: {meta['fingerprint_sha256']}", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload_encrypt.html')


# List encrypted files
@app.route('/files')
def files():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))
    files = list_encrypted_files()
    return render_template('files.html', files=files)


# Decrypt file route (downloads decrypted file)
@app.route('/decrypt/<filename>', methods=['GET'])
def decrypt(filename):
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))
    try:
        result = handle_decrypt_and_verify(filename)
    except FileNotFoundError:
        flash("Encrypted file or key not found.", "error")
        return redirect(url_for('files'))
    except ValueError as e:
        flash("Decryption failed or authentication tag mismatch.", "error")
        return redirect(url_for('files'))

    flash_msg = f"Decryption completed. Integrity verified: {result['verified']}. SHA-256 (decrypted): {result['decrypted_hash']}"
    flash(flash_msg, "success")
    # Option: let user download file or show link
    return redirect(url_for('files'))

# Where to store uploaded files for hashing
HASH_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "hash_inputs")
os.makedirs(HASH_UPLOAD_DIR, exist_ok=True)

# Route: compute & save hash
@app.route('/hash_file', methods=['GET', 'POST'])
def hash_file():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file provided.", "error")
            return redirect(request.url)
        f = request.files['file']
        if f.filename == '':
            flash("No selected file.", "error")
            return redirect(request.url)

        fname = secure_filename(f.filename)
        dest = os.path.join(HASH_UPLOAD_DIR, fname)
        f.save(dest)

        hex_digest, b64_digest = comp_sha256(dest)
        # Save hex to sidecar .sha256 file
        hash_path = dest + ".sha256"
        save_hash_to_file(hex_digest, hash_path)

        result = {
            "filename": fname,
            "hex": hex_digest,
            "b64": b64_digest,
            "hash_file": os.path.relpath(hash_path, BASE_DIR)
        }
        flash("Hash computed and saved.", "success")

    return render_template('hash_file.html', result=result)

# Route: verify integrity (upload file and provide hex or choose saved .sha256)
@app.route('/verify_file', methods=['GET', 'POST'])
def verify_file():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    verify_result = None
    if request.method == 'POST':
        # user can either upload a file + enter a hex digest OR pick an existing .sha256 path
        use_saved = request.form.get('use_saved', '')
        if use_saved and request.files.get('file') is None:
            flash("Please upload a file to verify.", "error")
            return redirect(request.url)

        # get uploaded file
        f = request.files.get('file')
        if not f or f.filename == '':
            flash("Please upload the file to verify.", "error")
            return redirect(request.url)

        fname = secure_filename(f.filename)
        dest = os.path.join(HASH_UPLOAD_DIR, "verify_" + fname)
        f.save(dest)

        # determine hex to compare
        hex_input = request.form.get('hex_digest', '').strip()
        saved_path = request.form.get('saved_hash_path', '').strip()

        if saved_path:
            # load from file (relative path accepted)
            try:
                if not os.path.isabs(saved_path):
                    saved_path = os.path.join(BASE_DIR, saved_path)
                orig_hex = load_hash_from_file(saved_path)
            except Exception as e:
                flash(f"Could not load saved hash: {e}", "error")
                return redirect(request.url)
        elif hex_input:
            orig_hex = hex_input
        else:
            flash("Please provide a hex digest or a saved .sha256 file path.", "error")
            return redirect(request.url)

        ok = verify_integrity(orig_hex, dest)
        verify_result = {"ok": ok, "expected": orig_hex}
        flash("Verification complete.", "success" if ok else "error")

    return render_template('verify_file.html', result=verify_result)

# Route: generate QR / fingerprint from hex (typed or uploaded file)
@app.route('/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    qr_path = None
    if request.method == 'POST':
        # accept either direct hex input, or uploaded file to hash
        hex_input = request.form.get('hex_digest', '').strip()
        f = request.files.get('file')
        if not hex_input and (not f or f.filename == ''):
            flash("Provide a hex digest or upload a file to generate its fingerprint.", "error")
            return redirect(request.url)

        if f and f.filename:
            fname = secure_filename(f.filename)
            dest = os.path.join(HASH_UPLOAD_DIR, "finger_" + fname)
            f.save(dest)
            hex_input, _ = comp_sha256(dest)

        # now hex_input contains the digest
        try:
            qr_rel = os.path.join("static", "generated", f"qr_{int(time.time())}.png")
            qr_abs = os.path.join(BASE_DIR, qr_rel)
            os.makedirs(os.path.dirname(qr_abs), exist_ok=True)
            gen_fingerprint(hex_input, qr_abs)
            qr_path = "/" + qr_rel  # URL path
            flash("Fingerprint (QR) generated.", "success")
        except Exception as e:
            flash(f"Could not generate QR: {e}", "error")

    return render_template('fingerprint.html', qr_path=qr_path)

if __name__ == "__main__":
    app.run(debug=True)
