from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)


# --- Работа с БД ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    # Таблица пользователей
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )'''
    )
    db.commit()
    # Добавить статус заявки (если ещё нет)
    cur = db.execute("PRAGMA table_info(requests)").fetchall()
    cols = [c['name'] for c in cur]
    if 'status' not in cols:
        db.execute(
            "ALTER TABLE requests ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
        )
        db.commit()
    # Расширение таблицы пользователей дополнительными полями
    cur = db.execute("PRAGMA table_info(users)").fetchall()
    user_cols = [c['name'] for c in cur]
    if 'service_name' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN service_name TEXT")
    if 'contact_info' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN contact_info TEXT")
    if 'address' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN address TEXT")
    if 'is_active' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    db.commit()
    # Таблица автозапчастей (с новыми полями)
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sku TEXT UNIQUE NOT NULL,
            price REAL NOT NULL,
            availability INTEGER NOT NULL,
            make TEXT NOT NULL,
            model TEXT NOT NULL,
            type TEXT NOT NULL,
            year INTEGER,
            description TEXT,
            compatibility TEXT,
            image_url TEXT
        )'''
    )
    db.commit()
    # Засеять тестовые данные, если таблица пуста
    cur = db.execute("SELECT COUNT(*) AS count FROM parts")
    if cur.fetchone()['count'] == 0:
        sample = [
            ('Фильтр масляный', 'OF123', 300.0, 15, 'Toyota', 'Camry', 'Фильтры', 2018,
             'Масляный фильтр для двигателя Toyota Camry', 'Toyota Camry 2012-2018',
             '/static/images/of123.jpg'),
            ('Тормозные колодки', 'BR456', 1200.5, 0, 'BMW', 'X5', 'Тормоза', 2020,
             'Колодки тормозные передние для BMW X5', 'BMW X5 2018-2021',
             '/static/images/br456.jpg'),
            ('Свеча зажигания', 'SP789', 250.0, 30, 'Honda', 'Civic', 'Двигатель', 2016,
             'Свеча с платиновым электродом для Honda Civic', 'Honda Civic 2012-2016',
             '/static/images/sp789.jpg'),
        ]
        for name, sku, price, avail, make, model, part_type, year, desc, comp, img in sample:
            db.execute(
                '''
                INSERT INTO parts
                    (name, sku, price, availability, make, model, type, year, description, compatibility, image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (name, sku, price, avail, make, model, part_type, year, desc, comp, img)
            )
        db.commit()

    # Таблица заявок
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )'''
    )
    db.commit()
    # Таблица позиций заявок
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS request_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            part_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id),
            FOREIGN KEY(part_id) REFERENCES parts(id)
        )'''
    )
    db.commit()

    cur = db.execute("PRAGMA table_info(requests)").fetchall()
    cols = [c['name'] for c in cur]
    if 'status' not in cols:
        db.execute("ALTER TABLE requests ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if 'admin_comment' not in cols:
        db.execute("ALTER TABLE requests ADD COLUMN admin_comment TEXT")
    db.commit()

    # Таблица отзывов
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(request_id) REFERENCES requests(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )'''
    )
    db.commit()

with app.app_context():
    init_db()


# --- Аутентификация ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            if user['is_active'] == 0:
                return render_template('login.html', error='Аккаунт деактивирован')
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('home'))
        return render_template('login.html', error='Неверные данные')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password_hash = generate_password_hash(request.form['password'])
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Пользователь существует')
    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- Страница «Каталог запчастей» ---
@app.route('/catalog')
def catalog():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Принять параметры фильтрации
    category = request.args.get('type', '')
    make     = request.args.get('make', '')
    model    = request.args.get('model', '')
    year     = request.args.get('year', '')
    db = get_db()
    query  = "SELECT * FROM parts WHERE 1=1"
    params = []
    if category:
        query += " AND type = ?";          params.append(category)
    if make:
        query += " AND make LIKE ?";        params.append(f"%{make}%")
    if model:
        query += " AND model LIKE ?";       params.append(f"%{model}%")
    if year:
        query += " AND year = ?";            params.append(year)
    parts = db.execute(query, params).fetchall()
    # Список всех категорий
    cats = [r['type'] for r in db.execute("SELECT DISTINCT type FROM parts").fetchall()]
    return render_template('catalog.html',
                           parts=parts,
                           categories=cats,
                           selected_type=category,
                           make=make,
                           model=model,
                           year=year)


# --- Страница деталей запчасти ---
@app.route('/part/<int:part_id>')
def part_detail(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    part = db.execute('SELECT * FROM parts WHERE id = ?', (part_id,)).fetchone()
    if not part:
        return 'Запчасть не найдена', 404
    return render_template('part_detail.html', part=part)


# --- Прочие заглушки ---
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    name      = request.args.get('name', '')
    make      = request.args.get('make', '')
    model     = request.args.get('model', '')
    part_type = request.args.get('type', '')
    db        = get_db()
    query     = "SELECT * FROM parts WHERE 1=1"
    params    = []
    if name:
        query += " AND name LIKE ?"
        params.append(f"%{name}%")
    if make:
        query  += " AND make LIKE ?"
        params.append(f"%{make}%")
    if model:
        query  += " AND model LIKE ?"
        params.append(f"%{model}%")
    if part_type:
        query  += " AND type = ?"
        params.append(part_type)
    parts = db.execute(query, params).fetchall()
    return render_template('home.html',
                           parts=parts,
                           name=name,
                           make=make,
                           model=model,
                           part_type=part_type)


@app.route('/requests')
def requests_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    reqs = db.execute(
        "SELECT * FROM requests WHERE user_id = ? AND status IN ('draft','pending') ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    return render_template('requests.html', requests=reqs)


@app.route('/orders')
def orders_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Жёстко завершаем только «не ожидающие» заявки
    date_from = request.args.get('date_from', '')
    date_to   = request.args.get('date_to', '')
    status    = request.args.get('status', '')
    db = get_db()
    query = "SELECT * FROM requests WHERE user_id = ? AND status != 'pending'"
    params = [session['user_id']]
    if status:
        query += " AND status = ?";      params.append(status)
    if date_from:
        query += " AND date(created_at) >= ?"; params.append(date_from)
    if date_to:
        query += " AND date(created_at) <= ?"; params.append(date_to)
    query += " ORDER BY created_at DESC"
    orders = db.execute(query, params).fetchall()
    # Список статусов для фильтра
    status_list = [r['status'] for r in db.execute(
        "SELECT DISTINCT status FROM requests WHERE user_id = ? AND status != 'pending'",
        (session['user_id'],)
    ).fetchall()]
    return render_template('requests.html',
                           requests=orders,
                           status_list=status_list,
                           date_from=date_from,
                           date_to=date_to,
                           selected_status=status)


# --- Отзывы ---
@app.route('/reviews')
def reviews():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    rows = db.execute(
        '''
        SELECT r.id, r.created_at, r.comment AS req_comment, r.status,
               rev.rating, rev.comment AS review_comment
        FROM requests r
        LEFT JOIN reviews rev ON r.id = rev.request_id AND rev.user_id = ?
        WHERE r.user_id = ? AND r.status != 'pending'
        ORDER BY r.created_at DESC
        ''',
        (session['user_id'], session['user_id'])
    ).fetchall()
    return render_template('reviews.html', requests=rows)


@app.route('/review/<int:request_id>', methods=['GET', 'POST'])
def leave_review(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    req = db.execute(
        "SELECT * FROM requests WHERE id = ? AND user_id = ? AND status != 'pending'",
        (request_id, session['user_id'])
    ).fetchone()
    if not req:
        return "Заявка не найдена или ещё не завершена", 404
    existing = db.execute(
        "SELECT * FROM reviews WHERE request_id = ? AND user_id = ?",
        (request_id, session['user_id'])
    ).fetchone()
    error   = None
    comment = existing['comment'] if existing else ''
    rating  = existing['rating']  if existing else ''
    if request.method == 'POST':
        rating = request.form.get('rating', '')
        comment = request.form.get('comment', '').strip()
        if not rating:
            error = 'Выберите рейтинг'
        elif not comment:
            error = 'Введите комментарий'
        else:
            if existing:
                db.execute(
                    'UPDATE reviews SET rating = ?, comment = ? WHERE id = ?',
                    (rating, comment, existing['id'])
                )
            else:
                db.execute(
                    'INSERT INTO reviews (request_id, user_id, rating, comment)'
                    ' VALUES (?, ?, ?, ?)',
                    (request_id, session['user_id'], rating, comment)
                )
            db.commit()
            return redirect(url_for('reviews'))
    return render_template('review_form.html',
                           request_id=request_id,
                           comment=comment,
                           rating=rating,
                           error=error)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if request.method == 'POST':
        service_name = request.form['service_name']
        contact_info = request.form['contact_info']
        address      = request.form['address']
        db.execute(
            'UPDATE users SET service_name = ?, contact_info = ?, address = ? WHERE id = ?',
            (service_name, contact_info, address, session['user_id'])
        )
        db.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# --- Создание новой заявки ---
@app.route('/request/new', methods=['GET', 'POST'])
def new_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    parts = db.execute('SELECT * FROM parts').fetchall()
    error = None

    if request.method == 'POST':
        comment = request.form.get('comment', '').strip()
        items = []
        for part in parts:
            qty = request.form.get(f'qty_{part["id"]}', '0')
            try:
                q = int(qty)
            except ValueError:
                q = 0
            if q > 0:
                items.append((part['id'], q))

        if not items:
            error = 'Выберите хотя бы одну запчасть и укажите количество'
        elif not comment:
            error = 'Укажите комментарий'
        if not error:
            cur = db.execute(
                'INSERT INTO requests (user_id, comment, status) VALUES (?, ?, ?)',
                (session['user_id'], comment, 'draft')
            )
            req_id = cur.lastrowid
            for part_id, q in items:
                db.execute(
                    'INSERT INTO request_items (request_id, part_id, quantity) VALUES (?, ?, ?)',
                    (req_id, part_id, q)
                )
            db.commit()
            return redirect(url_for('requests_page'))

    return render_template('create_request.html', parts=parts, error=error)


# --- Редактирование и отправка заявки ---
@app.route('/request/<int:request_id>/send', methods=['POST'])
def send_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    req = db.execute(
        "SELECT status FROM requests WHERE id = ? AND user_id = ?",
        (request_id, session['user_id'])
    ).fetchone()
    if req and req['status'] == 'draft':
        db.execute(
            "UPDATE requests SET status = 'pending' WHERE id = ?",
            (request_id,)
        )
        db.commit()
    return redirect(url_for('requests_page'))

@app.route('/request/<int:request_id>/edit', methods=['GET', 'POST'])
def edit_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    req = db.execute(
        "SELECT * FROM requests WHERE id = ? AND user_id = ?",
        (request_id, session['user_id'])
    ).fetchone()
    if not req or req['status'] != 'draft':
        return redirect(url_for('requests_page'))
    parts = db.execute('SELECT * FROM parts').fetchall()
    existing_items = {i['part_id']: i['quantity'] for i in db.execute(
        "SELECT * FROM request_items WHERE request_id = ?", (request_id,)
    ).fetchall()}
    error = None
    comment = req['comment']
    if request.method == 'POST':
        comment = request.form.get('comment', '').strip()
        items = []
        for part in parts:
            qty = request.form.get(f'qty_{part["id"]}', '0')
            try:
                q = int(qty)
            except ValueError:
                q = 0
            if q > 0:
                items.append((part['id'], q))
        if not items:
            error = 'Выберите хотя бы одну запчасть и укажите количество'
        elif not comment:
            error = 'Укажите комментарий'
        if not error:
            db.execute(
                'UPDATE requests SET comment = ? WHERE id = ?',
                (comment, request_id)
            )
            db.execute(
                'DELETE FROM request_items WHERE request_id = ?',
                (request_id,)
            )
            for pid, q in items:
                db.execute(
                    'INSERT INTO request_items (request_id, part_id, quantity) VALUES (?, ?, ?)',
                    (request_id, pid, q)
                )
            db.commit()
            return redirect(url_for('requests_page'))
    return render_template('edit_request.html',
                           parts=parts,
                           request=req,
                           existing_items=existing_items,
                           comment=comment,
                           error=error)


# --- Детали заявки и отмена заявки ---
@app.route('/request/<int:request_id>')
def request_detail(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    req = db.execute(
        "SELECT * FROM requests WHERE id = ? AND user_id = ?",
        (request_id, session['user_id'])
    ).fetchone()
    if not req:
        return "Заявка не найдена", 404
    items = db.execute(
        """
        SELECT ri.quantity, p.name, p.sku, p.price
        FROM request_items ri
        JOIN parts p ON ri.part_id = p.id
        WHERE ri.request_id = ?
        """, (request_id,)
    ).fetchall()
    return render_template('request_detail.html', request=req, items=items)

@app.route('/request/<int:request_id>/cancel', methods=['POST'])
def cancel_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    res = db.execute(
        "SELECT status FROM requests WHERE id = ? AND user_id = ?",
        (request_id, session['user_id'])
    ).fetchone()
    if res and res['status'] == 'pending':
        db.execute(
            "UPDATE requests SET status = 'cancelled' WHERE id = ?",
            (request_id,)
        )
        db.commit()
    return redirect(url_for('requests_page'))



# --- Смена пароля ---
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_pw  = request.form['old_password']
        new_pw  = request.form['new_password']
        confirm = request.form['confirm_password']
        db      = get_db()
        user    = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not check_password_hash(user['password'], old_pw):
            return render_template('change_password.html', error='Неверный текущий пароль')
        if new_pw != confirm:
            return render_template('change_password.html', error='Пароли не совпадают')
        db.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            (generate_password_hash(new_pw), session['user_id'])
        )
        db.commit()
        return render_template('change_password.html', success='Пароль успешно изменён')
    return render_template('change_password.html')

# --- Деактивация аккаунта ---
@app.route('/deactivate', methods=['POST'])
def deactivate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    db.execute('UPDATE users SET is_active = 0 WHERE id = ?', (session['user_id'],))
    db.commit()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)