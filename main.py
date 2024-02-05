from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import stripe

app = Flask(__name__)
app.secret_key = "supersecretkey"
stripe.api_key = "STRIPE_SECRET_KEY
###############################################################################
########################### X-Frame-Options for Vulnerabilities ###############
###############################################################################

@app.after_request
def apply_x_frame_options(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

##************************************************************************************************
## database function - this will create a database called users.db in the same 'folder' as the app.py file
##************************************************************************************************  

# SQLite database connection
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


##************************************************************************************************
## Creating my table in my database from ^ 
## This is a function called create_table that pulls in the value of the get_db from the function 
## and creates a table with the fields id, email, password, stripe_id, subscription_plan and subscription_status in it using the SQL statment.  
##************************************************************************************************  


# Create users table
def create_table():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            stripe_id TEXT,
            subscription_plan TEXT,
            subscription_status TEXT
        )
        """)



##************************************************************************************************
## Register Route - uses email and sha256 #HASH password features
##************************************************************************************************  



# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')

        with get_db() as conn:
            try:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
                flash('Registration successful!', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already exists!', 'danger')

    return render_template('register.html')


##************************************************************************************************
## Login Route
##************************************************************************************************  



# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = email  # Make sure to set the email in the session here
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login failed! Check your email and password', 'danger')

    return render_template('login.html')


##************************************************************************************************
## Dashboard Route
##************************************************************************************************  


# User dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


##************************************************************************************************
## HomePage Route
##************************************************************************************************  


# Home page
@app.route('/')
def home():
    return render_template('home.html')
    


##************************************************************************************************
## Logout Route
##************************************************************************************************  

@app.route('/logout')
def logout():
    # Remove user data from the session
    session.pop('user_id', None)
    return redirect(url_for('home'))


##************************************************************************************************
## Subscription Route if they exist in the database
##************************************************************************************************  


@app.route('/subscription', methods=['GET', 'POST'])
def subscription():
    if request.method == 'POST':
        # Get the user's chosen subscription plan and payment details
        plan = request.form['plan']
        token = request.form['stripeToken']

        # Check if 'email' is in the session
        email = session.get('email')
        if email:
            # Create a Stripe customer
            customer = stripe.Customer.create(
                email=email,
                source=token 
            )

            # Create a Stripe subscription
            subscription = stripe.Subscription.create(
                customer=customer.id,
                items=[{'plan': plan}]
            )

            # Update the user's subscription details in the SQLite database
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users
                    SET stripe_id = ?,
                        subscription_plan = ?,
                        subscription_status = 'active'
                    WHERE email = ?
                """, (customer.id, plan, email))
                conn.commit()

            flash('Subscription successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Handle the missing email appropriately, e.g., redirect to login
            flash('Please log in to subscribe.', 'warning')
            return redirect(url_for('login'))

    return render_template('subscription.html')


##************************************************************************************************
## Webhook Route
##************************************************************************************************  

# Modified webhook to handle subscription events
@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        # Verify the webhook signature
        event = stripe.Webhook.construct_event(payload, sig_header, "STRIPE_ENDPOINT_SECRET")

        # Handle different event types (e.g., subscription events)
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            customer_id = session['customer']
            # Update the user's subscription status to active
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users
                    SET subscription_status = 'active'
                    WHERE stripe_id = ?
                """, (customer_id,))
                conn.commit()
        elif event['type'] in ('invoice.paid', 'invoice.payment_succeeded'):
            # Update the user's subscription status to active
            customer_id = event['data']['object']['customer']
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users
                    SET subscription_status = 'active'
                    WHERE stripe_id = ?
                """, (customer_id,))
                conn.commit()

        return '', 200
    except (stripe.error.StripeError, ValueError):
        # Invalid payload or signature
        return '', 400


#@app.route('/')
#def index():
#  return render_template('index.html')

if __name__ == '__main__':
  create_table()
  app.run(debug=True, port=5000)
