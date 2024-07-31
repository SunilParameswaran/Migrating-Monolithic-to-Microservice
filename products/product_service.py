from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///product_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255))

def insert_dummy_products():
    dummy_products = [
        {
            'name': 'Nintendo Switch',
            'description': 'The new Nintendo flagship!',
            'price': 399.99,
            'image_url': 'https://upload.wikimedia.org/wikipedia/commons/thumb/8/88/Nintendo-Switch-wJoyCons-BlRd-Standing-FL.jpg/300px-Nintendo-Switch-wJoyCons-BlRd-Standing-FL.jpg'
        },
        {
            'name': 'SG Cricket Bat',
            'description': 'Master-crafted English willow!',
            'price': 29.99,
            'image_url': 'https://shop.teamsg.in/cdn/shop/products/LIAM-XTREME-scaled.jpg?v=1696576680&width=1946'
        },
        {
            'name': 'Mountain Dew',
            'description': 'Darr ke aage jeet hai',
            'price': 3.99,
            'image_url': 'https://www.jiomart.com/images/product/original/491349790/mountain-dew-750-ml-product-images-o491349790-p491349790-0-202203150326.jpg'
        },
        {
            'name': 'RCB Jersey',
            'description': 'Not winning :(',
            'price': 19.99,
            'image_url': 'https://m.media-amazon.com/images/I/41g+pgWuaKL._AC_UY1100_.jpg'
        },
        {
            'name': 'Tender Coconut',
            'description': 'No one reads this',
            'price': 0.99,
            'image_url': 'https://m.media-amazon.com/images/I/81Tpge1r7SL.jpg'
        }
    ]

    for product_data in dummy_products:
        product = Product(**product_data)
        db.session.add(product)

    db.session.commit()

@app.route('/products', methods=['GET'])
def get_all_products():
    products = Product.query.all()
    return jsonify([{'id':p.id,'name': p.name, 'description': p.description, 'price': p.price, 'image_url': p.image_url} for p in products])


if __name__ == '__main__':
    with app.app_context():
        
        db.create_all()
        insert_dummy_products()
    app.run(host="0.0.0.0", debug=True,  port=5002)
