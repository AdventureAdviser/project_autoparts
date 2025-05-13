from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

import os
from werkzeug.utils import secure_filename

# Настройка папки для сохранения изображений
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'images')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    if 'is_admin' not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    db.commit()
    # Создать пользователя-администратора по умолчанию, если таблица пуста
    cur = db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
    if cur['cnt'] == 0:
        db.execute(
            'INSERT INTO users (username, email, password, is_admin, is_active) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'admin@example.com', generate_password_hash('adminpass'), 1, 1)
        )
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
            session['is_admin'] = user['is_admin']
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
    cart = session.get('cart', [])
    # Получить список позиций текущего черновика
    row = db.execute(
        "SELECT id FROM requests WHERE user_id = ? AND status = 'draft' ORDER BY created_at DESC LIMIT 1",
        (session['user_id'],)
    ).fetchone()
    draft_items = []
    if row:
        draft_items = [r['part_id'] for r in db.execute(
            "SELECT part_id FROM request_items WHERE request_id = ?",
            (row['id'],)
        ).fetchall()]
    return render_template('catalog.html',
                           parts=parts,
                           categories=cats,
                           selected_type=category,
                           make=make,
                           model=model,
                           year=year,
                           cart=cart,
                           draft_items=draft_items)


# --- Страница деталей запчасти ---
@app.route('/part/<int:part_id>')
def part_detail(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    part = db.execute('SELECT * FROM parts WHERE id = ?', (part_id,)).fetchone()
    if not part:
        return 'Запчасть не найдена', 404
    # Определяем, откуда пришёл пользователь
    next_page = request.args.get('next', 'home')
    return render_template('part_detail.html', part=part, next_page=next_page)

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
    cart = session.get('cart', [])
    # Получить список позиций текущего черновика
    row = db.execute(
        "SELECT id FROM requests WHERE user_id = ? AND status = 'draft' ORDER BY created_at DESC LIMIT 1",
        (session['user_id'],)
    ).fetchone()
    draft_items = []
    if row:
        draft_items = [r['part_id'] for r in db.execute(
            "SELECT part_id FROM request_items WHERE request_id = ?",
            (row['id'],)
        ).fetchall()]
    return render_template('home.html',
                           parts=parts,
                           name=name,
                           make=make,
                           model=model,
                           part_type=part_type,
                           cart=cart,
                           draft_items=draft_items)


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
    # Подтягиваем информацию о уже оставленных отзывах
    rows = db.execute(
        '''
        SELECT r.*, rev.id AS review_id
        FROM requests r
        LEFT JOIN reviews rev
          ON r.id = rev.request_id AND rev.user_id = ?
        WHERE r.user_id = ? AND r.status != 'pending'
        ORDER BY r.created_at DESC
        ''',
        (session['user_id'], session['user_id'])
    ).fetchall()
    status_list = [r['status'] for r in db.execute(
        "SELECT DISTINCT status FROM requests WHERE user_id = ? AND status != 'pending'",
        (session['user_id'],)
    ).fetchall()]
    return render_template('requests.html',
                           requests=rows,
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
    cart = session.get('cart', [])
    parts = []
    if cart:
        placeholders = ','.join('?' for _ in cart)
        parts = db.execute(f'SELECT * FROM parts WHERE id IN ({placeholders})', tuple(cart)).fetchall()
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
            session['cart'] = []
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
    existing_items = {i['part_id']: i['quantity'] for i in db.execute(
        "SELECT * FROM request_items WHERE request_id = ?", (request_id,)
    ).fetchall()}
    placeholders = ','.join('?' for _ in existing_items)
    parts = []
    if existing_items:
        parts = db.execute(
            f"SELECT * FROM parts WHERE id IN ({placeholders})",
            tuple(existing_items.keys())
        ).fetchall()
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

# --- Управление корзиной ---

# --- Управление корзиной ---
@app.route('/cart/add/<int:part_id>')
def add_to_cart(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cart = session.get('cart', [])
    if part_id not in cart:
        cart.append(part_id)
        session['cart'] = cart
    next_page = request.args.get('next', 'home')
    return redirect(url_for(next_page))


# --- Админ-панель ---
@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403
    rows = db.execute(
        '''
        SELECT r.id, u.username, r.comment, r.created_at, r.status
        FROM requests r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
        '''
    ).fetchall()
    return render_template('admin_panel.html', requests=rows)

@app.route('/admin/request/<int:request_id>', methods=['GET', 'POST'])
def admin_request_detail(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403
    if request.method == 'POST':
        status = request.form['status']
        admin_comment = request.form.get('admin_comment', '').strip()
        db.execute(
            'UPDATE requests SET status = ?, admin_comment = ? WHERE id = ?',
            (status, admin_comment, request_id)
        )
        db.commit()
        return redirect(url_for('admin_panel'))
    req = db.execute(
        '''
        SELECT r.*, u.username
        FROM requests r
        JOIN users u ON r.user_id = u.id
        WHERE r.id = ?
        ''', (request_id,)
    ).fetchone()
    items = db.execute(
        '''
        SELECT ri.quantity, p.name, p.sku, p.price
        FROM request_items ri
        JOIN parts p ON ri.part_id = p.id
        WHERE ri.request_id = ?
        ''', (request_id,)
    ).fetchall()
    return render_template('admin_request_detail.html', request=req, items=items)


# --- Управление товарами (админ) ---

@app.route('/admin/parts')
def admin_parts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403
    parts = db.execute('SELECT * FROM parts ORDER BY id').fetchall()
    return render_template('admin_parts.html', parts=parts)

@app.route('/admin/part/<int:part_id>/edit', methods=['GET', 'POST'])
@app.route('/admin/part/<int:part_id>/edit', methods=['GET', 'POST'])
def admin_part_edit(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403

    if request.method == 'POST':
        # Получаем текущий товар, чтобы использовать его image_url, если файл не загружен
        part = db.execute('SELECT * FROM parts WHERE id = ?', (part_id,)).fetchone()
        if not part:
            return "Товар не найден", 404

        name         = request.form['name']
        sku          = request.form['sku']
        price        = request.form['price']
        availability = request.form['availability']
        make         = request.form['make']
        model        = request.form['model']
        part_type    = request.form['type']
        year         = request.form['year'] or None
        description  = request.form['description']
        compatibility= request.form['compatibility']

        # Обработка загруженного изображения
        image_file = request.files.get('image_file')
        if image_file and image_file.filename:
            filename    = secure_filename(image_file.filename)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(upload_path)
            image_url   = '/static/images/' + filename
        else:
            # если нового файла нет — сохраняем прежний URL
            image_url = part['image_url']

        # Обновляем запись в БД
        db.execute(
            '''
            UPDATE parts SET
                name=?, sku=?, price=?, availability=?,
                make=?, model=?, type=?, year=?,
                description=?, compatibility=?, image_url=?
            WHERE id=?
            ''',
            (name, sku, price, availability, make, model, part_type,
             year, description, compatibility, image_url, part_id)
        )
        db.commit()
        return redirect(url_for('admin_parts'))

    # GET: подгружаем part для формы
    part = db.execute('SELECT * FROM parts WHERE id = ?', (part_id,)).fetchone()
    if not part:
        return "Товар не найден", 404
    return render_template('admin_part_edit.html', part=part)
@app.route('/admin/part/new', methods=['GET', 'POST'])
def admin_part_new():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403
    if request.method == 'POST':
        # Сбор данных из формы
        name = request.form['name']
        sku = request.form['sku']
        price = request.form['price']
        availability = request.form['availability']
        make = request.form['make']
        model = request.form['model']
        part_type = request.form['type']
        year = request.form['year'] or None
        description = request.form['description']
        compatibility = request.form['compatibility']
        # Обработка изображения (как в редактировании)
        image_file = request.files.get('image_file')
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(upload_path)
            image_url = '/static/images/' + filename
        else:
            image_url = ''
        # Сохранение новой запчасти
        db.execute(
            '''
            INSERT INTO parts
                (name, sku, price, availability, make, model, type, year, description, compatibility, image_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (name, sku, price, availability, make, model, part_type,
             year, description, compatibility, image_url)
        )
        db.commit()
        return redirect(url_for('admin_parts'))
    # GET: используем тот же шаблон, но без данных part
    return render_template('admin_part_edit.html', part={})

@app.route('/admin/part/<int:part_id>/delete', methods=['POST'])
def admin_part_delete(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['is_admin'] != 1:
        return "Доступ запрещён", 403
    db.execute('DELETE FROM parts WHERE id = ?', (part_id,))
    db.commit()
    return redirect(url_for('admin_parts'))
@app.route('/cart/remove/<int:part_id>')
def remove_from_cart(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cart = session.get('cart', [])
    if part_id in cart:
        cart.remove(part_id)
        session['cart'] = cart
    next_page = request.args.get('next', 'home')
    return redirect(url_for(next_page))

# --- Управление черновиком заявки ---
@app.route('/draft/add/<int:part_id>')
def draft_add(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user_id = session['user_id']
    # Найти или создать черновик
    row = db.execute(
        "SELECT id FROM requests WHERE user_id = ? AND status = 'draft' ORDER BY created_at DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    if row:
        draft_id = row['id']
    else:
        cur = db.execute(
            "INSERT INTO requests (user_id, comment, status) VALUES (?, ?, 'draft')",
            (user_id, '',)
        )
        draft_id = cur.lastrowid
    # Добавить позицию, если её нет
    exists = db.execute(
        "SELECT 1 FROM request_items WHERE request_id = ? AND part_id = ?",
        (draft_id, part_id)
    ).fetchone()
    if not exists:
        db.execute(
            "INSERT INTO request_items (request_id, part_id, quantity) VALUES (?, ?, ?)",
            (draft_id, part_id, 1)
        )
        db.commit()
    next_page = request.args.get('next', 'home')
    return redirect(url_for(next_page))

@app.route('/draft/remove/<int:part_id>')
def draft_remove(part_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user_id = session['user_id']
    row = db.execute(
        "SELECT id FROM requests WHERE user_id = ? AND status = 'draft' ORDER BY created_at DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    if row:
        draft_id = row['id']
        db.execute(
            "DELETE FROM request_items WHERE request_id = ? AND part_id = ?",
            (draft_id, part_id)
        )
        db.commit()
    next_page = request.args.get('next', 'home')
    return redirect(url_for(next_page))

if __name__ == '__main__':
    app.run(debug=True)