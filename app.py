from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_from_directory
from functools import wraps
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__, static_folder='uploads')
app.secret_key = 'your_secret_key'

# Định nghĩa hàm role_required trước khi sử dụng nó trong các route
# Đây là hàm chính, nhận vào danh sách các quyền hạn (roles) cần thiết để truy cập một trang.
def role_required(*roles):
     # Hàm này là một decorator, nghĩa là sẽ thay đổi cách hoạt động của hàm khác (f) để kiểm tra quyền của người dùng.
    def decorator(f):
        @wraps(f)
        # Hàm này là hàm bao bọc (wrapper) thực hiện kiểm tra trước khi cho phép gọi hàm f.
        def decorated_function(*args, **kwargs):
            # Kiểm tra xem người dùng đã đăng nhập hay chưa (bằng cách xem 'role' có trong session không).
            if 'role' not in session:
                 # Hiển thị thông báo yêu cầu đăng nhập.
                flash("Please log in first.")
                # Chuyển hướng người dùng đến trang đăng nhập.
                return redirect(url_for('login_form'))
             # Kiểm tra xem quyền hạn của người dùng có trong danh sách quyền cần thiết không.
            elif session['role'] not in roles:
                flash("You do not have permission to access this page.") # Thông báo không có quyền truy cập.
                return redirect(url_for('index'))  # Chuyển hướng đúng đến trang chủ.
  # Chuyển hướng đến trang chủ.
            return f(*args, **kwargs)  # Nếu người dùng có quyền, tiếp tục thực hiện hàm gốc (f).
        return decorated_function
    return decorator



# Tạo kết nối tới cơ sở dữ liệu SQLite có tên 'projectdb1.db'.
def get_db_connection():
    # Kết nối này được lưu trong biến `conn`.
    conn = sqlite3.connect('projectdb1.db')
    # Thiết lập `row_factory` để trả về dữ liệu dưới dạng `sqlite3.Row`,
    # cho phép truy cập các cột theo tên, giúp dễ đọc và làm việc với dữ liệu.
    conn.row_factory = sqlite3.Row 
    return conn  # Trả về kết nối `conn` để sử dụng trong các truy vấn tiếp theo. 

def hash_existing_passwords():
   # Tạo kết nối tới cơ sở dữ liệu SQLite có tên 'projectdb1.db'.
    conn = sqlite3.connect('projectdb1.db')
    cursor = conn.cursor()
    
    # Retrieve all users from NHANVIEN table
    cursor.execute("SELECT MaNV, pass FROM NHANVIEN")
    users = cursor.fetchall()
    
       # Lặp qua từng người dùng để kiểm tra và mã hóa mật khẩu nếu cần.
    for user in users:
        ma_nv, plain_password = user
        # Skip if password is None
        if plain_password is None:
            print(f"Skipping user {ma_nv} because the password is None.")
            continue
         # Kiểm tra nếu mật khẩu chưa được mã hóa (không bắt đầu bằng "$2b$", dấu hiệu của bcrypt).
        if not plain_password.startswith("$2b$"):
            # Mã hóa mật khẩu với bcrypt.
            hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
             # Cập nhật lại mật khẩu đã mã hóa vào cơ sở dữ liệu.
            cursor.execute("UPDATE NHANVIEN SET pass = ? WHERE MaNV = ?", (hashed_password, ma_nv))
            print(f"Updated password for MaNV: {ma_nv}")# In thông báo khi cập nhật thành công.
    
    # Commit the changes and close the connection
    conn.commit()  # Lưu tất cả thay đổi vào cơ sở dữ liệu.
    conn.close() # Đóng kết nối với cơ sở dữ liệu.

 # Gọi hàm để mã hóa mật khẩu của tất cả người dùng.
hash_existing_passwords()

@app.route('/uploads/<filename>')
def static_files(filename):
    return send_from_directory('uploads', filename)
#########################################################
# Định nghĩa route cho trang chủ ('/'), nghĩa là khi người dùng truy cập vào địa chỉ trang web chính.
@app.route('/')
# Hàm `index` sẽ xử lý yêu cầu và trả về nội dung trang chủ.
def index():
    # Hàm này sẽ hiển thị (render) trang HTML có tên 'index.html' từ thư mục templates.
    return render_template('index.html')
#########################################################
# Định nghĩa route cho trang đăng nhập ('/login_form'), hỗ trợ cả phương thức GET và POST.
@app.route('/login_form', methods=['GET', 'POST'])
def login_form():
    # Nếu người dùng gửi biểu mẫu đăng nhập (POST), xử lý thông tin đăng nhập.
    if request.method == 'POST':
        username = request.form['username'] # Lấy tên đăng nhập từ biểu mẫu.
        password = request.form['password'] # Lấy mật khẩu từ biểu mẫu.
        conn = get_db_connection() # Kết nối với cơ sở dữ liệu.
        # Truy vấn để tìm người dùng dựa trên tên đăng nhập.
        user = conn.execute(
            "SELECT * FROM NHANVIEN WHERE user_name = ?", (username,)
        ).fetchone() 
        # Đóng kết nối cơ sở dữ liệu.
        conn.close()
        # Kiểm tra mật khẩu sử dụng bcrypt
        if user and bcrypt.checkpw(password.encode(), user['pass'].encode()):
            # Nếu người dùng tồn tại và mật khẩu khớp, đăng nhập thành công.
            session['username'] = username   # Lưu tên đăng nhập vào session.
            session['role'] = user['Vaitro']  # Lưu vai trò của người dùng vào session.
            flash("Login successful!") # Hiển thị thông báo thành công.
            return redirect(url_for('dashboard')) # Chuyển hướng đến trang dashboard
        else:
            flash("Invalid username or password.") # Thông báo khi tên đăng nhập hoặc mật khẩu không đúng
            return redirect(url_for('login_form')) # Quay lại trang đăng nhập.
    # Nếu yêu cầu là GET, hiển thị trang đăng nhập (login_form.html).
    return render_template('login_form.html')
######################### DASHBOARD ################################
#dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash("Please log in first.")
        return redirect(url_for('login_form'))
######################### RECRUITMENT ################################
# xem thông tin tuyển dụng
@app.route('/recruitment')
def recruitment():
    conn = get_db_connection()
    current_date = datetime.today().isoformat()  # Get today's date in ISO format
    query = """
    SELECT 
        TTTuyenDung.*, 
        DotTuyenDung.NgayKT 
    FROM 
        TTTuyenDung 
    JOIN 
        DotTuyenDung 
    ON 
        TTTuyenDung.MaDot = DotTuyenDung.MaDTD
    WHERE 
        TTTuyenDung.Posted = "Đã đăng" AND 
        DotTuyenDung.NgayKT > ?
    """
    recruitment_data = conn.execute(query, (current_date,)).fetchall()
    conn.close()
    return render_template('recruitment.html', recruitment_data=recruitment_data)
######################## UPLOAD #################################
#Set Up File Upload Directory: Add configurations for file storage:
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.isdir(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# hiển thị một biểu mẫu ứng tuyển cho một vị trí tuyển dụng cụ thể
@app.route('/apply/<ma_tttd>', methods=['GET', 'POST'])
def apply_form(ma_tttd):
    if request.method == 'POST':
        try:
            # Debug: Log form submission
            print("Form submission received.")

            # Get form data
            name = request.form.get('Hoten')
            email = request.form.get('Email')
            position = request.form.get('Vitri')
            print(f"Form Data: Name={name}, Email={email}, Position={position}")

            # Handle file uploads
            cv_file = request.files.get('cv')
            photo_file = request.files.get('photo')

            # Check if files were uploaded
            if not (cv_file and photo_file):
                print("File uploads missing.")
                return "File uploads missing."

            # Debug: Log uploaded file names
            print(f"Files received: CV={cv_file.filename}, Photo={photo_file.filename}")

            # Save files to the upload folder
            cv_filename = secure_filename(cv_file.filename)
            photo_filename = secure_filename(photo_file.filename)
            cv_path = os.path.join(app.config['UPLOAD_FOLDER'], cv_filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            cv_file.save(cv_path)
            photo_file.save(photo_path)

            # Debug: Log saved file paths
            print(f"Files saved: CV={cv_path}, Photo={photo_path}")

            # Save data to the database
            conn = sqlite3.connect('projectdb1.db')
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO HOSO_UNGVIEN 
                (Hoten, Email, Vitri, MaTTTD, CV_FilePath, Photo_FilePath) 
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, email, position, ma_tttd, cv_path, photo_path)
            )
            conn.commit()
            conn.close()

            # Debug: Confirm database insertion
            print("Data saved to database.")

            return "Application Submitted Successfully!"
        except Exception as e:
            # Debug: Log any exceptions
            print(f"Error occurred: {e}")
            return f"An error occurred: {e}"

    # Render the form for GET request
    return render_template('apply_form.html', ma_tttd=ma_tttd)

######################### NỘP ĐƠN ################################
@app.route('/submit_application', methods=['POST'])
def submit_application():
    # Retrieve form data
    ngaynop = datetime.now().date()
    vitri = request.form['Vitri']
    cmnd = request.form['CMND']
    hoten = request.form['Hoten']
    ngaysinh = request.form['Ngaysinh']
    skills = request.form['Skills']
    sdt = request.form['SDT']
    email = request.form['Email']
    ma_tttd = request.form['MaTTTD']
    trangthai = "Pending"
    
    # Handle file uploads
    cv_file = request.files.get('cv')
    photo_file = request.files.get('photo')

    # Check if files were uploaded
    if not (cv_file and photo_file):
        print("File uploads missing.")
        return "File uploads missing."

    # Debug: Log uploaded file names
    print(f"Files received: CV={cv_file.filename}, Photo={photo_file.filename}")

    # Save files to the upload folder
    cv_filename = secure_filename(cv_file.filename)
    photo_filename = secure_filename(photo_file.filename)
    cv_path = os.path.join(app.config['UPLOAD_FOLDER'], cv_filename)
    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
    cv_file.save(cv_path)
    photo_file.save(photo_path)

    # Debug: Log saved file paths
    print(f"Files saved: CV={cv_path}, Photo={photo_path}")

    conn = get_db_connection()

    # Get the last MaHS_UV value
    last_id = conn.execute("SELECT MaHS_UV FROM HOSO_UNGVIEN ORDER BY MaHS_UV DESC LIMIT 1").fetchone()
    if last_id:
        # Extract number and increment
        last_number = int(last_id['MaHS_UV'][2:])  # Remove 'UV' prefix and convert to integer
        new_number = last_number + 1
    else:
        # Start with 1 if no entries exist
        new_number = 1

    # Format new MaHS_UV as 'UVxx'
    ma_hs_uv = f"UV{new_number:02d}"

    # Insert data into the database
    conn.execute(
        "INSERT INTO HOSO_UNGVIEN (MaHS_UV, Ngaynop, Vitri, CMND, Hoten, Ngaysinh, Skills, SDT, Email, MaTTTD, TrangThai, CV_FilePath, Photo_FilePath) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ma_hs_uv, ngaynop, vitri, cmnd, hoten, ngaysinh, skills, sdt, email, ma_tttd, trangthai, cv_path, photo_path)
    )
    conn.commit()
    conn.close()

    flash("Your application has been submitted successfully!")
    return redirect(url_for('recruitment'))

######################## Đánh giá hồ sơ ứng viên #################################
@app.route('/applications', methods=['GET'])
@role_required('HR')
def applications():
    conn = get_db_connection()

    # Lấy danh sách đợt tuyển dụng đang diễn ra
    current_date = datetime.now().strftime('%Y-%m-%d')
    recruitments = conn.execute("""
        SELECT MaDTD, NgayBD, NgayKT 
        FROM DotTuyenDung
        WHERE NgayKT > ?
    """, (current_date,)).fetchall()

    # Lấy mã đợt tuyển dụng và trạng thái từ query string
    ma_dtd = request.args.get('ma_dtd', default=None)
    filter_status = request.args.get('filter_status', default=None)

    # Câu truy vấn chính
    query = """
        SELECT 
        HOSO_UNGVIEN.MaHS_UV,
        HOSO_UNGVIEN.Hoten,
        HOSO_UNGVIEN.Vitri,
        HOSO_UNGVIEN.Email,
        HOSO_UNGVIEN.SDT,
        HOSO_UNGVIEN.Skills,
        HOSO_UNGVIEN.CV_FilePath,
        HOSO_UNGVIEN.Photo_FilePath,
        HOSO_UNGVIEN.TrangThai,
        HOSO_UNGVIEN.IsPassed,
        TTTuyenDung.MaTTTD,
        DotTuyenDung.MaDTD,
        DotTuyenDung.NgayBD,
        DotTuyenDung.NgayKT
        FROM HOSO_UNGVIEN
        LEFT JOIN TTTuyenDung
            ON HOSO_UNGVIEN.MaTTTD = TTTuyenDung.MaTTTD
        LEFT JOIN DotTuyenDung
            ON TTTuyenDung.MaDot = DotTuyenDung.MaDTD
        """

    # Thêm điều kiện lọc nếu có
    params = [current_date]
    conditions = ["DotTuyenDung.NgayKT > ?"]

    if ma_dtd:
        conditions.append("DotTuyenDung.MaDTD = ?")
        params.append(ma_dtd)

    if filter_status == 'dat_yeu_cau':
        conditions.append("HOSO_UNGVIEN.TrangThai = 'Đạt yêu cầu'")
    elif not filter_status:
        conditions.append("HOSO_UNGVIEN.TrangThai != 'Đạt yêu cầu'")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # Thực thi truy vấn
    applications_data = conn.execute(query, params).fetchall()
    conn.close()

    # Trả về template
    return render_template(
        'applications.html',
        applications_data=applications_data,
        recruitments=recruitments,
        selected_dtd=ma_dtd,
        filter_status=filter_status
    )

###################### Cập nhật trạng thái cho xem hồ sơ ứng viên ###################################
@app.route('/update_status', methods=['POST'])
@role_required('HR')
def update_status():
    ma_hs_uv = request.form.get('MaHS_UV')
    trangthai = request.form.get('TrangThai')

    VALID_STATUSES = ["Đạt yêu cầu", "Không đạt yêu cầu", "Đang xét duyệt"]
    
    if not ma_hs_uv or trangthai not in VALID_STATUSES:
        flash("Dữ liệu không hợp lệ. Vui lòng thử lại.", "error")
        return redirect(url_for('applications'))

    conn = get_db_connection()
    try:
        conn.execute("UPDATE HOSO_UNGVIEN SET TrangThai = ? WHERE MaHS_UV = ?", (trangthai, ma_hs_uv))
        conn.commit()
        flash(f"Cập nhật trạng thái ứng viên {ma_hs_uv} thành công.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Lỗi khi cập nhật trạng thái: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('applications'))


@app.route('/update_ispassed', methods=['POST'])
@role_required('HR')
def update_ispassed():
    ma_hs_uv = request.form.get('MaHS_UV')
    is_passed = request.form.get('IsPassed')

    VALID_ISPASSED_VALUES = ["Đậu", "Không đậu", "Chưa xét"]

    if not ma_hs_uv or is_passed not in VALID_ISPASSED_VALUES:
        flash("Dữ liệu không hợp lệ. Vui lòng thử lại.", "error")
        return redirect(url_for('applications'))

    conn = get_db_connection()
    try:
        # Cập nhật giá trị IsPassed
        conn.execute("UPDATE HOSO_UNGVIEN SET IsPassed = ? WHERE MaHS_UV = ?", (is_passed, ma_hs_uv))
        conn.commit()

        # Nếu IsPassed là "Đậu", thêm thông tin vào bảng PHIEUPHONGVAN
        if is_passed == "Đậu":
            # Fetch thông tin liên quan để tạo phiếu phỏng vấn
            applicant = conn.execute("SELECT * FROM HOSO_UNGVIEN WHERE MaHS_UV = ?", (ma_hs_uv,)).fetchone()
            if not applicant:
                raise ValueError(f"Không tìm thấy ứng viên với ID {ma_hs_uv}.")

            ma_tttd = applicant['MaTTTD']
            if not ma_tttd:
                raise ValueError(f"Không tìm thấy mã thông tin tuyển dụng (MaTTTD) cho ứng viên {ma_hs_uv}.")

            # Lấy mã đợt tuyển dụng
            ma_dtd_row = conn.execute("""
                SELECT DotTuyenDung.MaDTD
                FROM TTTuyenDung
                JOIN DotTuyenDung ON TTTuyenDung.MaDot = DotTuyenDung.MaDTD
                WHERE TTTuyenDung.MaTTTD = ?
            """, (ma_tttd,)).fetchone()

            if not ma_dtd_row:
                raise ValueError(f"Không tìm thấy đợt tuyển dụng (MaDTD) liên kết với MaTTTD {ma_tttd}.")

            ma_dtd = ma_dtd_row['MaDTD']

            # Tạo mã phiếu phỏng vấn mới
            next_id = conn.execute("""
                SELECT COALESCE(MAX(CAST(SUBSTR(MaPhieu, 3) AS INTEGER)), 0) + 1 AS NextID FROM PHIEUPHONGVAN
            """).fetchone()['NextID']
            ma_phieu = f"PV{next_id:02d}"

            # Thiết lập thông tin phiếu phỏng vấn
            ngay_phong_van = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
            gio_phong_van = "07:00"
            dia_diem = "Hà Nội"
            trang_thai = "Chưa duyệt"

            # Thêm vào bảng PHIEUPHONGVAN
            conn.execute("""
                INSERT INTO PHIEUPHONGVAN (MaPhieu, MaUV, NgayPhongVan, GioPhongVan, DiaDiem, TrangThai, MaDTD)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ma_phieu, ma_hs_uv, ngay_phong_van, gio_phong_van, dia_diem, trang_thai, ma_dtd))
            conn.commit()

        flash(f"Cập nhật IsPassed của ứng viên {ma_hs_uv} thành công.", "success")
    except ValueError as ve:
        conn.rollback()
        flash(str(ve), "error")
    except Exception as e:
        conn.rollback()
        flash(f"Lỗi khi cập nhật IsPassed: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('applications'))


########################### LÊN LỊCH PHỎNG VẤN ##############################
@app.route('/schedule_interviews', methods=['GET'])
def schedule_interviews():
    conn = get_db_connection()

    # Lấy danh sách đợt tuyển dụng
    recruitments_query = "SELECT MaDTD, NgayBD, NgayKT FROM DOTTUYENDUNG"
    recruitments = conn.execute(recruitments_query).fetchall()

    # Lấy danh sách phỏng vấn
    ma_dtd = request.args.get('ma_dtd')  # Lọc theo mã đợt tuyển dụng
    query = """
        SELECT 
            PHIEUPHONGVAN.MaPhieu, PHIEUPHONGVAN.NgayPhongVan, PHIEUPHONGVAN.GioPhongVan, 
            PHIEUPHONGVAN.DiaDiem, PHIEUPHONGVAN.TrangThai,
            HOSO_UNGVIEN.Hoten, HOSO_UNGVIEN.Vitri, HOSO_UNGVIEN.Email, HOSO_UNGVIEN.SDT
        FROM PHIEUPHONGVAN
        JOIN HOSO_UNGVIEN ON PHIEUPHONGVAN.MaUV = HOSO_UNGVIEN.MaHS_UV
        WHERE PHIEUPHONGVAN.TrangThai = 'Chưa duyệt'
    """
    params = []
    if ma_dtd:
        query += " AND PHIEUPHONGVAN.MaDTD = ?"
        params.append(ma_dtd)

    interviews = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        'schedule_interviews.html',
        recruitments=recruitments,
        interviews=interviews,
        selected_ma_dtd=ma_dtd
    )

# Route để cập nhật từng trường riêng lẻ
@app.route('/update_field', methods=['POST'])
def update_field():
    # Lấy thông tin từ form
    ma_phieu = request.form.get('MaPhieu')
    field = request.form.get('field')  # Trường được cập nhật (column name)
    value = request.form.get('value')  # Giá trị mới

    if not (ma_phieu and field and value):
        flash("Thiếu thông tin để cập nhật!", "danger")
        return redirect(url_for('schedule_interviews'))

    # Xác thực tên cột để tránh SQL Injection
    allowed_fields = ['NgayPhongVan', 'GioPhongVan', 'DiaDiem', 'TrangThai']
    if field not in allowed_fields:
        flash("Trường dữ liệu không hợp lệ!", "danger")
        return redirect(url_for('schedule_interviews'))

    # Cập nhật cơ sở dữ liệu
    conn = get_db_connection()
    query = f"UPDATE PHIEUPHONGVAN SET {field} = ? WHERE MaPhieu = ?"
    conn.execute(query, (value, ma_phieu))
    conn.commit()
    conn.close()

    flash(f"Cập nhật {field} thành công!", "success")
    return redirect(url_for('schedule_interviews'))
######################### Xem hội đồng tuyển dụng ################################
# Định tuyến để hiển thị trang HTML với danh sách thả xuống
@app.route('/committee')
@role_required('Giám đốc')
def committee():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Lấy danh sách các mã đợt tuyển dụng
    cursor.execute("SELECT DISTINCT MaDot FROM HoiDongTuyenDung")
    ma_dot_values = [row["MaDot"] for row in cursor.fetchall()]

    conn.close()
    return render_template('committee.html', ma_dot_values=ma_dot_values)

@app.route('/get_committee', methods=['POST'])
@role_required('Giám đốc')
def get_committee():
    ma_dot = request.form['MaDot']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Truy vấn để lấy tất cả thành viên trong hội đồng dựa trên MaDot
    query = """
    SELECT 
        NHANVIEN.Vaitro, 
        NHANVIEN.TenNV 
    FROM 
        HoiDongTuyenDung
    JOIN 
        CTHD ON HoiDongTuyenDung.MaHDTD = CTHD.MaHDTD
    JOIN 
        NHANVIEN ON CTHD.MaNV = NHANVIEN.MaNV
    WHERE 
        HoiDongTuyenDung.MaDot = ?
    """
    cursor.execute(query, (ma_dot,))
    results = cursor.fetchall()

    # Chuyển đổi kết quả thành danh sách các từ điển
    committee_details = [{"Chucvu": row["Vaitro"], "TenNV": row["TenNV"]} for row in results]

    conn.close()
    return jsonify(committee_details)
########################## Đăng JOB ###############################
#Lấy vị trí
def get_vitri():
    connection = get_db_connection()  # Sử dụng hàm kết nối đã có
    cursor = connection.cursor()
    cursor.execute("SELECT MaVitri, TenVitri FROM VITRI")  # Truy vấn dữ liệu từ bảng VITRI
    data = cursor.fetchall()  # Lấy toàn bộ kết quả
    connection.close()  # Đóng kết nối để tránh rò rỉ tài nguyên
    return [{'MaVitri': row['MaVitri'], 'TenVitri': row['TenVitri']} for row in data]

def get_dot_tuyen_dung():
    # Lấy ngày hiện tại
    today = datetime.now().strftime('%Y-%m-%d')  # Định dạng ngày: YYYY-MM-DD

    connection = get_db_connection()  # Hàm kết nối cơ sở dữ liệu đã có
    cursor = connection.cursor()

    # Truy vấn các đợt tuyển dụng còn hạn
    cursor.execute("""
        SELECT MaDTD, NgayBD, NgayKT 
        FROM DotTuyenDung 
        WHERE NgayKT >= ?
    """, (today,))

    data = cursor.fetchall()  # Lấy toàn bộ kết quả
    connection.close()  # Đóng kết nối

    # Trả về danh sách đợt tuyển dụng còn hạn
    return [
        {
            'MaDTD': row['MaDTD'],
            'NgayBD': row['NgayBD'],
            'NgayKT': row['NgayKT']
        }
        for row in data
    ]

def get_trinhdo():
    connection = get_db_connection()  # Hàm kết nối cơ sở dữ liệu
    cursor = connection.cursor()

    # Truy vấn dữ liệu từ bảng TRINHDO
    cursor.execute("SELECT MaTrinhdo, TenTrinhDo FROM TRINHDO")
    data = cursor.fetchall()
    connection.close()  # Đóng kết nối để tránh rò rỉ tài nguyên

    # Trả về danh sách trình độ
    return [{'MaTrinhdo': row['MaTrinhdo'], 'TenTrinhDo': row['TenTrinhDo']} for row in data]

@app.route('/post_job')
@role_required('Trưởng phòng')
def post_job():
    user_name = session.get('username')  # Lấy thông tin user từ session

    if not user_name:
        return redirect(url_for('login_form'))  # Chuyển hướng nếu chưa đăng nhập

    # Truy vấn phòng ban của user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT MaPB FROM NHANVIEN WHERE user_name = ?', (user_name,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return "<p style='color: red;'>Không tìm thấy thông tin nhân viên!</p>", 404

    user_department = user['MaPB']  # Lấy MaPB từ kết quả truy vấn

    # Lấy danh sách vị trí, đợt tuyển dụng và trình độ
    vitri_list = get_vitri()
    dot_tuyen_dung_list = get_dot_tuyen_dung()
    trinhdo_list = get_trinhdo()

    return render_template(
        'post_job.html',
        user_department=user_department,
        vitri_list=vitri_list,
        dot_tuyen_dung_list=dot_tuyen_dung_list,
        trinhdo_list=trinhdo_list
    )

@app.route('/submit_job', methods=['POST'])
@role_required('Giám đốc', 'Trưởng phòng')
def submit_job():
    conn = None  # Khởi tạo conn để tránh lỗi UnboundLocalError
    try:
        # Lấy dữ liệu từ form
        MaPB = request.form.get('MaPB')
        MaDot = request.form.get('MaDTD')
        MaVitri = request.form.get('MaVitri')
        YeuCau = request.form.get('YeuCau')
        SoLuong = int(request.form.get('SoLuong', 0))
        TrangThai = "Đang xét duyệt"
        Motacongviec = request.form.get('Motacongviec')
        Mucluong = float(request.form.get('Mucluong', 0.0))
        Noilamviec = request.form.get('Noilamviec')
        MaTrinhdo = request.form.get('MaTrinhdo')
        print("Mã phòng ban: ", MaPB)
        # Tự động lấy ngày bắt đầu và ngày kết thúc
        NgayBD = datetime.now().strftime('%Y-%m-%d')  # Ngày hiện tại
        NgayKT = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')  # Sau 7 ngày

        # Kết nối cơ sở dữ liệu
        conn = get_db_connection()
        if not conn:
            raise ConnectionError("Không thể kết nối cơ sở dữ liệu.")
        
        cursor = conn.cursor()

        # Lấy mã cuối cùng từ bảng TTTuyenDung
        last_id_row = cursor.execute("SELECT MaTTTD FROM TTTuyenDung ORDER BY MaTTTD DESC LIMIT 1").fetchone()

        # Tự động tăng mã TTTuyenDung
        if last_id_row:
            last_id = last_id_row['MaTTTD']
            new_id_number = int(last_id[2:]) + 1
            MaTTTD = f"TT{new_id_number:02d}"
        else:
            MaTTTD = "TT01"

        # Chèn dữ liệu vào bảng TTTuyenDung
        query = """
            INSERT INTO TTTuyenDung (MaTTTD, MaDot, MaPB, MaVitri, YeuCau, SoLuong, TrangThai, Motacongviec, Mucluong, Noilamviec, MaTrinhdo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (MaTTTD, MaDot, MaPB, MaVitri, YeuCau, SoLuong, TrangThai, Motacongviec, Mucluong, Noilamviec, MaTrinhdo))

        # Lưu thay đổi
        conn.commit()
        flash(f"Job posted successfully with MaDot: {MaDot}, NgayBD: {NgayBD}, NgayKT: {NgayKT}", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
        app.logger.error(f"Error in submit_job: {e}")
    finally:
        if conn:  # Chỉ đóng kết nối nếu `conn` được khởi tạo
            conn.close()
    return redirect(url_for('post_job'))

#Nhân viên duyệt
@app.route('/employee_tasks', methods=['GET', 'POST'])
@role_required('HR') 
def employee_tasks():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Lấy danh sách công việc đã được duyệt
    cursor.execute('SELECT * FROM TTTuyenDung WHERE TrangThai = "Đã duyệt"')
    tasks = cursor.fetchall()

    conn.close()
    return render_template('employee_tasks.html', tasks=tasks)

@app.route('/post_task/<task_id>', methods=['POST'])
@role_required('HR')
def post_task(task_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Cập nhật trạng thái Posted thành "Đã đăng"
    cursor.execute('UPDATE TTTuyenDung SET Posted = "Đã đăng" WHERE MaTTTD = ?', (task_id,))
    conn.commit()
    conn.close()

    # Chuyển hướng lại trang danh sách công việc
    return redirect(url_for('employee_tasks'))


# Giám đốc duyệt
@app.route('/pending_jobs')
@role_required('Giám đốc')
def pending_jobs():
    success = request.args.get('success', False)  # Lấy giá trị từ query string
    conn = get_db_connection()
    cursor = conn.cursor()

    # Truy vấn danh sách job với trạng thái "Đang duyệt"
    cursor.execute('SELECT MaTTTD, Motacongviec, TrangThai FROM TTTuyenDung WHERE TrangThai != "Đã duyệt"')
    jobs = cursor.fetchall()
    conn.close()

    return render_template('pending_jobs.html', jobs=jobs, success=success)

#Cập nhật trạng thái job của giám đốc
@app.route('/review_job/<job_id>', methods=['GET', 'POST'])
@role_required('Giám đốc')
def review_job(job_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    print(f"Job ID received: {job_id}")
    if request.method == 'POST':
        # Lấy trạng thái mới từ form
        new_status = request.form['TrangThai']

        # Cập nhật trạng thái trong cơ sở dữ liệu
        cursor.execute(
            'UPDATE TTTuyenDung SET TrangThai = ? WHERE MaTTTD = ?',
            (new_status, job_id)
        )
        conn.commit()
        conn.close()

        # Sau khi cập nhật, chuyển hướng về trang pending_jobs kèm thông báo thành công
        return redirect(url_for('pending_jobs', success=True))

    # Truy vấn thông tin chi tiết job
    cursor.execute('SELECT * FROM TTTuyenDung WHERE MaTTTD = ?', (job_id,))
    job = cursor.fetchone()
    conn.close()

    if not job:
        return "<p style='color: red;'>Job không tồn tại hoặc không thể hiển thị thông tin.</p>", 404

    # Truyền thông tin job vào template
    return render_template('review_job.html', job=job)
#########################################################
# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login_form'))
######################### Gửi Mail ################################
@app.route('/send_email', methods=['POST'])
def send_email():
    # Lấy data
    to_email = request.form.get('Email')
    candidate_name = request.form.get('Hoten')
    interview_date = request.form.get('NgayPhongVan')
    interview_time = request.form.get('GioPhongVan')
    interview_location = request.form.get('DiaDiem')
    # Nếu có tất cả data thì :
    if to_email and candidate_name and interview_date and interview_time and interview_location:
        try:
            send_html_email(to_email, candidate_name, interview_date, interview_time, interview_location)
            flash(f"Email sent successfully to {to_email}!", "success")
        except Exception as e:
            flash(f"Failed to send email: {e}", "danger")
    else:
        flash("Missing required information for email.", "danger")
    return redirect(url_for('schedule_interviews'))

def send_html_email(to_email, candidate_name, interview_date, interview_time, interview_location):
    from_email = "ntt12ctn1@gmail.com"  # Không thay đổi
    password = "xgtg auvh gytq hjju"  # Không thay đổi
    subject = "Thư Mời Phỏng Vấn"

    # Nội dung HTML của email
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Thư Mời Phỏng Vấn</title>
      </head>
      <body>
        <p>Xin chào, {candidate_name}!</p>
        <p>
          Lời đầu tiên, chúng tôi xin cảm ơn bạn vì đã quan tâm đến vị trí ứng tuyển của công ty.
          Thông qua hồ sơ mà bạn đã gửi về, chúng tôi nhận thấy bạn có kiến thức chuyên môn phù hợp với vị trí mà chúng tôi đang tuyển.
        </p>
        <p>
          Chúng tôi trân trọng kính mời bạn đến tham gia buổi phỏng vấn của công ty chúng tôi với thông tin sau:
        </p>
        <ul>
          <li><strong>Thời gian:</strong> {interview_time}, ngày {interview_date}</li>
          <li><strong>Địa điểm:</strong> {interview_location}</li>
        </ul>
        <p>
          Để buổi phỏng vấn diễn ra thuận lợi, bạn vui lòng phản hồi email này trong vòng 24 giờ kể từ khi nhận được.
          Mọi thắc mắc, vui lòng liên hệ qua số điện thoại: 0123456789 hoặc email: abc@company.com.
        </p>
        <p>Trân trọng,<br />Nhà Tuyển Dụng</p>
      </body>
    </html>
    """

    # Tạo email với định dạng HTML
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(html_content, 'html'))

    # Kết nối tới server Gmail và gửi email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Bắt đầu mã hóa TLS
        server.login(from_email, password)  # Đăng nhập
        server.sendmail(from_email, to_email, msg.as_string())  # Gửi email
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/send_email_pass', methods=['POST'])
def send_email_pass():
    ma_uv = request.form['MaUV']  # Lấy mã ứng viên từ form

    # Kết nối cơ sở dữ liệu
    conn = get_db_connection()
    try:
        # Truy vấn để lấy thông tin ứng viên từ bảng HOSO_UNGVIEN
        result = conn.execute(
            "SELECT Email, Hoten FROM HOSO_UNGVIEN WHERE MaHS_UV = ?", (ma_uv,)
        ).fetchone()

        if not result:
            # Nếu không tìm thấy ứng viên
            flash("Applicant not found in the database.", "danger")
            return redirect(url_for('applicant_Information'))

        # Lấy email và tên từ kết quả truy vấn
        to_email = result['Email']
        candidate_name = result['Hoten']
        print(f"Preparing to send email to {to_email} for {candidate_name}")

        # Gửi email
        try:
            send_html_email_pass(to_email, candidate_name)  # Gửi email
            flash(f"Email sent successfully to {to_email}!", "success")

            # Sau khi gửi email thành công, thêm bản ghi vào bảng LOIMOILAMVIEC
            ma_loi_moi = f"LMLV{ma_uv[-2:]}{int(datetime.now().timestamp()) % 10000}"  # Sinh mã lời mời duy nhất
            ngay_gui = datetime.now().strftime("%Y-%m-%d")  # Ngày gửi
            muc_luong = 10000  # Ví dụ: mức lương cố định hoặc lấy từ bảng khác
            ma_vi_tri = "VT01"  # Mã vị trí giả định, cập nhật từ dữ liệu thực tế
            trang_thai = "Đã gửi"

            # Thêm bản ghi vào bảng LOIMOILAMVIEC
            conn.execute("""
                INSERT INTO LOIMOILAMVIEC (MaLoiMoi, MaUV, MaViTri, NgayGui, MucLuong, TrangThai)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ma_loi_moi, ma_uv, ma_vi_tri, ngay_gui, muc_luong, trang_thai))
            conn.commit()
            flash(f"Invitation record added for applicant {candidate_name}.", "success")

        except Exception as email_error:
            flash(f"Failed to send email: {email_error}", "danger")
            print(f"Failed to send email: {email_error}")

    except sqlite3.Error as db_error:
        # Xử lý lỗi cơ sở dữ liệu
        flash(f"Database error: {db_error}", "danger")
        print(f"Database error: {db_error}")
    finally:
        conn.close()  # Đảm bảo đóng kết nối cơ sở dữ liệu

    # Quay lại trang applicant_Information
    return redirect(url_for('applicant_Information'))


def send_html_email_pass(to_email, candidate_name):
    from_email = "ntt12ctn1@gmail.com" # không được thay đổi
    password = "xgtg auvh gytq hjju"  # không được thay đổi
    subject = "Thư Mời Làm Việc"

    # Nội dung HTML của email
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Thư Mời Làm Việc</title>
      </head>
      <body>
        <p>Xin chào, {candidate_name}!</p>
        <p>
          Chúng tôi rất vui mừng thông báo rằng bạn đã đạt yêu cầu tuyển dụng cho vị
          trí mà bạn đã ứng tuyển.
        </p>
        <p>Xin vui lòng liên hệ lại với chúng tôi để hoàn tất quy trình.</p>
        <p>Trân trọng,<br />Nhà Tuyển Dụng</p>
      </body>
    </html>
    """

    # Tạo email với định dạng HTML
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(html_content, 'html'))

    # Kết nối tới server Gmail và gửi email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Bắt đầu mã hóa TLS
        server.login(from_email, password)  # Đăng nhập
        server.sendmail(from_email, to_email, msg.as_string())  # Gửi email
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
########################### Thông tin ứng viên ##############################
@app.route('/applicant_Information', methods=['GET', 'POST'])
@role_required('Giám đốc', 'Trưởng phòng')
def applicant_Information():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # POST: Cập nhật kết quả phỏng vấn và câu trả lời
        if request.method == 'POST':
            ma_phieu = request.form.get('MaPhieu')
            ket_qua_pv = request.form.get('KetQuaPV')
            answer = request.form.get('answer')

            if not ma_phieu or not ket_qua_pv:
                flash("Dữ liệu không hợp lệ!", "error")
                return redirect(url_for('applicant_Information'))

            # Cập nhật bảng PHIEUPHONGVAN
            cursor.execute("""
                UPDATE PHIEUPHONGVAN
                SET KetQuaPV = ?, answer = ?
                WHERE MaPhieu = ?
            """, (ket_qua_pv, answer, ma_phieu))
            conn.commit()

            flash(f"Kết quả phỏng vấn cho phiếu {ma_phieu} đã được cập nhật.", "success")

        # GET: Lọc danh sách ứng viên chưa được gửi email
        ma_dtd = request.args.get('ma_dtd')
        # Lấy ngày hiện tại
        current_date = datetime.now().date()

        # Cập nhật truy vấn SQL
        recruitments_query = """
            SELECT MaDTD, NgayBD, NgayKT 
            FROM DOTTUYENDUNG
            WHERE NgayKT >= ?
        """
        recruitments = cursor.execute(recruitments_query, (current_date,)).fetchall()

        # Lọc các ứng viên chưa được gửi email
        query = """
            SELECT 
                PHIEUPHONGVAN.MaPhieu, 
                PHIEUPHONGVAN.MaUV, 
                PHIEUPHONGVAN.MaNV, 
                PHIEUPHONGVAN.NgayPhongVan, 
                PHIEUPHONGVAN.GioPhongVan, 
                PHIEUPHONGVAN.DiaDiem, 
                PHIEUPHONGVAN.KetQuaPV, 
                PHIEUPHONGVAN.TrangThai,
                PHIEUPHONGVAN.answer
            FROM PHIEUPHONGVAN
            LEFT JOIN LOIMOILAMVIEC 
                ON PHIEUPHONGVAN.MaUV = LOIMOILAMVIEC.MaUV
            WHERE (LOIMOILAMVIEC.TrangThai IS NULL OR LOIMOILAMVIEC.TrangThai = 'Chưa gửi')
        """
        params = []
        if ma_dtd:
            query += " AND PHIEUPHONGVAN.MaDTD = ?"
            params.append(ma_dtd)

        interviews = cursor.execute(query, params).fetchall()

        return render_template(
            'applicant_Information.html',
            interviews=interviews,
            recruitments=recruitments,
            selected_dtd=ma_dtd
        )
    except Exception as e:
        app.logger.error(f"Lỗi: {e}")
        flash(f"Có lỗi xảy ra: {e}", "error")
        return redirect(url_for('applicant_Information'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
######################## Thống kê #################################
@app.route('/interview_statistics', methods=['GET'])
def interview_statistics():
    ma_dtd = request.args.get('ma_dtd')  # Lấy mã đợt tuyển dụng từ query parameters
    conn = get_db_connection()
    try:
        # Lấy danh sách các đợt tuyển dụng
        recruitments = conn.execute("""
            SELECT MaDTD, NgayBD, NgayKT
            FROM DotTuyenDung
        """).fetchall()

        # Khởi tạo các thống kê
        total_applicants = 0
        failed_applicants = 0
        passed_count = 0
        failed_count = 0
        total_count = 0

        if ma_dtd:  # Nếu có mã đợt tuyển dụng
            # Tổng số ứng viên ứng tuyển trong đợt tuyển dụng
            total_applicants_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM HOSO_UNGVIEN
                JOIN TTTuyenDung ON TTTuyenDung.MaTTTD = HOSO_UNGVIEN.MaTTTD
                JOIN DotTuyenDung dtd ON TTTuyenDung.MaDot = dtd.MaDTD
                WHERE dtd.MaDTD = ?
            """, (ma_dtd,)).fetchone()
            total_applicants = total_applicants_row['count'] if total_applicants_row else 0

            # Số lượng ứng viên không đạt yêu cầu ứng tuyển trong đợt tuyển dụng
            failed_applicants_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM HOSO_UNGVIEN
                JOIN TTTuyenDung ON HOSO_UNGVIEN.MaTTTD = TTTuyenDung.MaTTTD
                JOIN DotTuyenDung ON TTTuyenDung.MaDot = DotTuyenDung.MaDTD
                WHERE HOSO_UNGVIEN.TrangThai = 'Không đạt yêu cầu'
                  AND DotTuyenDung.MaDTD = ?
            """, (ma_dtd,)).fetchone()
            failed_applicants = failed_applicants_row['count'] if failed_applicants_row else 0

            # Số lượng đậu phỏng vấn
            passed_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
                WHERE KetQuaPV = 'Dat' AND MaDTD = ?
            """, (ma_dtd,)).fetchone()
            passed_count = passed_count_row['count'] if passed_count_row else 0

            # Số lượng không đậu phỏng vấn
            failed_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
                WHERE KetQuaPV = 'Khong dat' AND MaDTD = ?
            """, (ma_dtd,)).fetchone()
            failed_count = failed_count_row['count'] if failed_count_row else 0

            # Tổng số người được phỏng vấn
            total_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
                WHERE MaDTD = ?
            """, (ma_dtd,)).fetchone()
            total_count = total_count_row['count'] if total_count_row else 0

        else:  # Nếu không có mã đợt tuyển dụng
            app.logger.info("Fetching overall statistics.")

            # Tổng số ứng viên ứng tuyển trong tất cả các đợt tuyển dụng
            total_applicants_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM HOSO_UNGVIEN
            """).fetchone()
            total_applicants = total_applicants_row['count'] if total_applicants_row else 0

            # Số lượng ứng viên không đạt yêu cầu ứng tuyển trong tất cả đợt tuyển dụng
            failed_applicants_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM HOSO_UNGVIEN
                JOIN TTTuyenDung ON HOSO_UNGVIEN.MaTTTD = TTTuyenDung.MaTTTD
                JOIN DotTuyenDung ON TTTuyenDung.MaDot = DotTuyenDung.MaDTD
                WHERE HOSO_UNGVIEN.TrangThai = 'Không đạt yêu cầu'
            """).fetchone()
            failed_applicants = failed_applicants_row['count'] if failed_applicants_row else 0

            # Số lượng đậu phỏng vấn
            passed_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
                WHERE KetQuaPV = 'Dat'
            """).fetchone()
            passed_count = passed_count_row['count'] if passed_count_row else 0

            # Số lượng không đậu phỏng vấn
            failed_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
                WHERE KetQuaPV = 'Khong dat'
            """).fetchone()
            failed_count = failed_count_row['count'] if failed_count_row else 0

            # Tổng số người được phỏng vấn
            total_count_row = conn.execute("""
                SELECT COUNT(*) AS count
                FROM PHIEUPHONGVAN
            """).fetchone()
            total_count = total_count_row['count'] if total_count_row else 0

        # Truyền dữ liệu đến giao diện
        return render_template(
            'interview_statistics.html',
            total_applicants=total_applicants,
            failed_applicants=failed_applicants,
            passed_count=passed_count,
            failed_count=failed_count,
            total_count=total_count,
            recruitments=recruitments,
            selected_dtd=ma_dtd
        )
    except Exception as e:
        app.logger.error(f"Error fetching statistics: {e}")
        flash("Có lỗi xảy ra khi lấy thống kê!", "error")
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

########################## Xem chi tiết hồ sơ ứng viên ##############################
@app.route('/applicants/<ma_hs_uv>', methods=['GET'])
@role_required('Giám đốc', 'Trưởng phòng')
def applicant_detail(ma_hs_uv):
    conn = get_db_connection()
    try:
        # Truy vấn thông tin chi tiết ứng viên
        applicant = conn.execute("""
            SELECT *
            FROM HOSO_UNGVIEN
            WHERE MaHS_UV = ?
        """, (ma_hs_uv,)).fetchone()

        # Kiểm tra nếu không tìm thấy ứng viên
        if not applicant:
            flash("Ứng viên không tồn tại!", "error")
            return redirect(url_for('dashboard'))  # Sửa endpoint thành 'dashboard'

        # Render giao diện chi tiết ứng viên
        return render_template('applicant_detail.html', applicant=applicant)
    except Exception as e:
        app.logger.error(f"Error fetching applicant detail: {e}")
        flash("Có lỗi xảy ra khi lấy thông tin ứng viên!", "error")
        return redirect(url_for('dashboard'))  # Sửa endpoint thành 'dashboard'
    finally:
        conn.close()

# ####################### Tạo đợt tuyển dụng ####################
# Hàm sinh mã Đợt tuyển dụng tự động
def generate_ma_dtd():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MaDTD FROM DotTuyenDung ORDER BY MaDTD DESC LIMIT 1")
    last_ma_dtd = cursor.fetchone()
    conn.close()

    if last_ma_dtd:
        last_number = int(last_ma_dtd[0][3:])  # Tách phần số sau 'DTD'
        new_number = last_number + 1
    else:
        new_number = 1  # Nếu chưa có mã nào, bắt đầu từ 1

    return f"DTD{new_number:02d}"  # Định dạng 'DTDxx'

# Hàm sinh mã Hội đồng tuyển dụng tự động
def generate_ma_hd():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MaHDTD FROM HoiDongTuyenDung ORDER BY MaHDTD DESC LIMIT 1")
    last_ma_hdtd = cursor.fetchone()
    conn.close()

    if last_ma_hdtd:
        last_number = int(last_ma_hdtd[0][4:])  # Tách phần số sau 'HDTD'
        new_number = last_number + 1
    else:
        new_number = 1  # Nếu chưa có mã nào, bắt đầu từ 1

    return f"HDTD{new_number:02d}"  # Định dạng 'HDTDxx'

# Hàm sinh mã Chi tiết Hội đồng tự động
def generate_ma_cthd():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MaHD FROM CTHD ORDER BY MaHD DESC LIMIT 1")
    last_ma_cthd = cursor.fetchone()
    conn.close()

    if last_ma_cthd:
        last_number = int(last_ma_cthd[0][4:])  # Tách phần số sau 'CTHD'
        new_number = last_number + 1
    else:
        new_number = 1  # Nếu chưa có mã nào, bắt đầu từ 1

    return f"CTHD{new_number:02d}"  # Định dạng 'CTHDxx'

# Hàm kiểm tra mã đã tồn tại trong bảng CTHD hay chưa
def is_mahd_exists(mahd):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM CTHD WHERE MaHD = ?", (mahd,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

# Hàm lấy MaNV của người dùng hiện tại từ user_name
def get_user_id(user_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MaNV FROM NHANVIEN WHERE user_name = ?", (user_name,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Route tạo Đợt tuyển dụng
@app.route('/create_recruitment', methods=['GET', 'POST'])
@role_required('Giám đốc', 'Trưởng phòng')
def create_recruitment():
    if request.method == 'POST':
        # Lấy dữ liệu từ form
        ngay_bd = request.form['NgayBD']
        ngay_kt = request.form['NgayKT']

        # Lấy thông tin người dùng hiện tại
        current_user = session.get('username')  # Lấy user_name từ session
        print(f"Người dùng hiện tại: {current_user}")
        current_user_id = get_user_id(current_user)  # Lấy MaNV từ user_name
        print(f"MaNV của người dùng hiện tại: {current_user_id}")

        if not current_user_id:
            return render_template('create_recruitment.html', error="Người dùng hiện tại không tồn tại trong hệ thống.")

        # Tạo mã tự động
        ma_dtd = generate_ma_dtd()
        print(f"MaDTD được sinh: {ma_dtd}")
        ma_hdtd = generate_ma_hd()
        print(f"MaHDTD được sinh: {ma_hdtd}")

        # Kết nối cơ sở dữ liệu
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # 1. Thêm Đợt tuyển dụng
            print(f"Thêm DotTuyenDung: MaDTD={ma_dtd}, NgayBD={ngay_bd}, NgayKT={ngay_kt}")
            cursor.execute(
                'INSERT INTO DotTuyenDung (MaDTD, NgayBD, NgayKT) VALUES (?, ?, ?)',
                (ma_dtd, ngay_bd, ngay_kt)
            )

            # 2. Thêm Hội đồng tuyển dụng
            print(f"Thêm HoiDongTuyenDung: MaHDTD={ma_hdtd}, MaDot={ma_dtd}")
            cursor.execute(
                'INSERT INTO HoiDongTuyenDung (MaHDTD, MaDot) VALUES (?, ?)',
                (ma_hdtd, ma_dtd)
            )

            # 3. Thêm Giám đốc vào Chi tiết Hội đồng
            cursor.execute(
                'SELECT MaNV FROM NHANVIEN WHERE Chucvu = "Trưởng phòng" AND Vaitro = "Giám đốc" LIMIT 1'
            )
            giam_doc = cursor.fetchone()
            if giam_doc:
                ma_hd_gd = generate_ma_cthd()
                print(f"Thêm CTHD (Giám đốc): MaHD={ma_hd_gd}, MaNV={giam_doc[0]}")
                cursor.execute(
                    'INSERT INTO CTHD (MaHD, MaNV, MaHDTD, ChucVu) VALUES (?, ?, ?, ?)',
                    (ma_hd_gd, giam_doc[0], ma_hdtd, 'Chủ tịch')
                )
                conn.commit()
            else:
                raise Exception("Không tìm thấy Giám đốc trong cơ sở dữ liệu.")

            # 4. Thêm Trưởng phòng (người dùng hiện tại) vào Chi tiết Hội đồng
            ma_hd_tp = generate_ma_cthd()
            print(f"Thêm CTHD (Trưởng phòng - người hiện tại): MaHD={ma_hd_tp}, MaNV={current_user_id}")
            cursor.execute(
                'INSERT INTO CTHD (MaHD, MaNV, MaHDTD, ChucVu) VALUES (?, ?, ?, ?)',
                (ma_hd_tp, current_user_id, ma_hdtd, 'Thành viên')
            )

            # Lưu thay đổi
            conn.commit()
            print("Commit thành công!")
            return render_template('create_recruitment.html', success="Tạo Đợt tuyển dụng thành công!")

        except Exception as e:
            conn.rollback()
            print(f"Lỗi xảy ra: {e}")
            return render_template('create_recruitment.html', error=f"Lỗi: {str(e)}")

        finally:
            conn.close()

    return render_template('create_recruitment.html')

###########################################
if __name__ == '__main__':
    app.run(debug=True)
