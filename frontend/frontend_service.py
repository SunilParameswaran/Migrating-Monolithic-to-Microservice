from flask import Flask, render_template, session, redirect, url_for, flash, request  # Import request

import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

AUTH_SERVICE_URL = 'http://auth_container:5007'
PRODUCT_SERVICE_URL = 'http://products_container:5002'
CART_SERVICE_URL = 'http://cart_container:5003'
ORDER_SERVICE_URL = 'http://order_container:5004'  # Define ORDER_SERVICE_URL

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {
            'username': request.form['username'],
            'password': request.form['password']
        }
        response = requests.post(f'{AUTH_SERVICE_URL}/register', json=data)

        if response.status_code == 200:
            flash('Registration successful. Please log in.', 'success')
        elif response.status_code == 401:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            flash('Registration failed. Please try again.', 'danger')

        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        response = requests.post(f'{AUTH_SERVICE_URL}/login', json={'username': username, 'password': password})

        if response.status_code == 200:
            user_id = response.json().get('user_id')
            session['username'] = username
            session['user_id'] = user_id
            flash('Login successful!', 'success')
            return redirect(url_for('products'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/products')
def products():
    response = requests.get(f'{PRODUCT_SERVICE_URL}/products')
    products = response.json()
    return render_template('products.html', products=products)


@app.route('/add_to_cart/<string:product_name>/<float:price>', methods=['POST'])
def add_to_cart(product_name,price):
    if 'user_id' not in session:
        flash('Please log in to add items to your cart.', 'warning')
        return redirect(url_for('login'))

    data = {
        'product_name': product_name,
        'price':price,
        'user_id': session['user_id']
    }
    response = requests.post(f'{CART_SERVICE_URL}/add_to_cart', json=data)
    flash(response.json()['message'], 'info')
    return redirect(url_for('products'))


@app.route('/view_cart')
def view_cart():
    if 'user_id' not in session:
        flash('Please log in to view your cart.', 'warning')
        return redirect(url_for('login'))

    response = requests.get(f'{CART_SERVICE_URL}/view_cart/{session["user_id"]}')
    cart_items = response.json()['cart_items']
    total = response.json()['total']
    return render_template('cart.html', cart_items=cart_items,total =total)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Please log in to proceed to checkout.', 'warning')
            return redirect(url_for('login'))

        data = {
            'user_id': session['user_id'],
            'address': request.form['address'],
            'payment_info': request.form['payment_info']
        }
        response = requests.post(f'{ORDER_SERVICE_URL}/checkout', json=data)
        flash(response.json()['message'], 'info')
        return redirect(url_for('products'))

    return render_template('checkout.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)
