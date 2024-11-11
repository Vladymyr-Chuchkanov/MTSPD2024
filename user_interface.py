import queue
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from tkinter import ttk
from connector import Connector
import random
import string
import time
import threading

def on_entry_click(event):
    if password_field.get() == placeholder_text:
        password_field.delete(0, tk.END)
        password_field.config(fg='black')

def on_focusout(event):
    if password_field.get() == '':
        password_field.insert(0, placeholder_text)
        password_field.config(fg='gray')
        password_field.focus_displayof()
        print(1)



def write_files(files):
    if len(files)==0:
        return
    folder_path = filedialog.askdirectory()
    saved_files_list = ""
    info_window.config(text="")
    if folder_path:

        for file_name, file_content in files:
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, 'wb') as file:
                    file.write(file_content)
            except:
                info_window.config(text="Error while saving file: " + file_path)
                continue
            saved_files_list += file_path + "\n"
    info_window.config(text=info_window.cget("text")+"Successfully saved files:\n" + saved_files_list)


def read_files():
    file_paths = filedialog.askopenfilenames(filetypes=[("All files", "*.*")])
    info_window.config(text="")
    files_data.clear()
    if file_paths:
        for file_path in file_paths:
            file_name = os.path.basename(file_path)
            try:
                with open(file_path, 'rb') as file:
                    file_content = file.read()
                    files_data.append([file_name, file_content])
                    info_window.config(text=info_window.cget("text")+"File was read: "+file_name+"\n")
            except:
                info_window.config(text="Error while reading file: " + file_path)
                continue


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in string.punctuation for char in password):
        return False
    return True


def generate_strong_password():
    length = 12
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    special = random.choice(string.punctuation)
    all_characters = lowercase + uppercase + digit + special + string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_characters) for _ in range(length - 4))
    password += lowercase + uppercase + digit + special
    password = ''.join(random.sample(password, len(password)))
    return password

def set_password():
    password = generate_strong_password()
    password_field.delete(0, tk.END)
    password_field.config(fg='black')
    password_field.insert(0, password)
    info_window.config(text="Save generated password!")

def update_progress_bar(size):
    max_length = int(size)//size_time_coef
    if max_length == 0:
        max_length = 1
    print(max_length)
    progress_bar['value'] = 0
    for i in range(max_length):
        time.sleep(5)
        progress_bar['value'] = progress_bar['value'] + progress_bar_length/max_length
        root.update_idletasks()


def start_progress_bar(size):
    threading.Thread(target=update_progress_bar, args=(size,)).start()

def encrypt_files_with_progress(temp_data, password):
    errors, temp_data = conn.encrypt_files(temp_data, password)
    result_queue.put((errors, temp_data))

def start_encryption(temp_data, password):
    threading.Thread(target=encrypt_files_with_progress, args=(temp_data, password)).start()

def check_password():
    password = password_field.get()
    if password == placeholder_text or password == '':
        password = ''
    else:
        if not is_strong_password(password):
            info_window.config(
                text="Password: " + password + " is weak! \nA strong password should be at least 8 characters long and include a mix of uppercase letters, lowercase letters, numbers, and special characters (e.g., @, #, $, %, ^, &, *).")
            return -1
    return password


def encrypt_files():
    if len(files_data) == 0:
        info_window.config(text="No files selected!")
        return
    password = check_password()
    if password == -1:
        return

    size, errors, temp_data = conn.check_files(files_data)
    if len(errors) != 0:
        info_window.config(text=errors)

    algorithm = algorithm_selection.get()
    conn.select_algorithm(algorithm)

    txt = info_window.cget("text")
    info_window.config(text=txt+"\n encryption is in progress!")
    start_progress_bar(size)
    start_encryption(temp_data, password)
    threading.Thread(target=check_results).start()



def check_results():
    i=0
    while True:
        try:
            errors, temp_data = result_queue.get_nowait()
            progress_bar['value'] = progress_bar_length
            if len(errors) != 0:
                info_window.config(text=errors)
            write_files(temp_data)
            break
        except queue.Empty:
            time.sleep(1)
            i += 1
    print(i)
    files_data.clear()


def decrypt_files():
    if len(files_data) == 0:
        info_window.config(text="No files selected!")
        return
    password = password_field.get()
    if password == placeholder_text:
        password = ""
    info_window.config(text="decryption is in progress!")
    errors, temp_data = conn.decrypt_files(files_data, password)
    files_data.clear()
    if len(errors) != 0:
        info_window.config(text=errors)
    write_files(temp_data)



if __name__=="__main__":

    root = tk.Tk()
    root.title("Encrypting app")
    root.geometry("800x330")
    files_data = []
    placeholder_text = "enter password"
    conn = Connector()
    algorithm_names = conn.get_algorithms()
    progress_bar_length = 100
    size_time_coef = 1024*1024*100
    result_queue = queue.Queue()

    top_frame_0 = tk.Frame(root)
    top_frame_0.pack(pady=10, fill="x")

    top_frame_1 = tk.Frame(root)
    top_frame_1.pack(pady=10, fill="x")

    top_frame_2 = tk.Frame(root)
    top_frame_2.pack(pady=10, fill="x")

    top_frame_3 = tk.Frame(root)
    top_frame_3.pack(pady=10, fill="x")

    top_frame_4 = tk.Frame(root)
    top_frame_4.pack(pady=10, fill="x")

    algorithm_selection_label = tk.Label(top_frame_0, text="Select encryption algorithm")
    algorithm_selection_label.pack(side="left", padx=3)
    algorithm_selection = ttk.Combobox(top_frame_0, values=algorithm_names, state="readonly")
    algorithm_selection.set(algorithm_names[0])
    algorithm_selection.pack(side="left", padx=0)

    upload_button = tk.Button(top_frame_0, text="Upload files", command=read_files)
    upload_button.pack(side="left", padx=5, expand=True, fill='x')

    encrypt_button = tk.Button(top_frame_1, text="Encrypt", command=encrypt_files)
    encrypt_button.pack(side="left", padx=5, expand=True, fill='x')

    decrypt_button = tk.Button(top_frame_1, text="Decrypt", command=decrypt_files)
    decrypt_button.pack(side="left", padx=5, expand=True, fill='x')

    password_field = tk.Entry(top_frame_2, bd=2, relief="sunken",fg='gray')
    password_field.insert(0, placeholder_text)
    password_field.bind('<FocusIn>', on_entry_click)
    password_field.bind('<FocusOut>', on_focusout)
    password_field.pack(side="left", padx=5, expand=True, fill='x')

    generate_password_button = tk.Button(top_frame_2, text="Generate password", command=set_password)
    generate_password_button.pack(side="left", padx=5)

    info_window = tk.Label(top_frame_3, text="", wraplength=580, bd=2, relief="sunken", height=5, anchor="nw")
    info_window.pack(padx=5, pady=5, fill="both", expand=True)

    progress_bar = ttk.Progressbar(top_frame_4, orient="horizontal", length=progress_bar_length, mode="determinate")
    progress_bar.pack(padx=5, pady=5, fill='x')

    root.mainloop()










