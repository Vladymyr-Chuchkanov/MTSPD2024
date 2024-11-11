import os
import importlib.util
import inspect
import subprocess


from connector import Connector


algorithms_directory = "algorithms/"

current_algorithms = [algorithms_directory+f for f in os.listdir(algorithms_directory) if f.endswith(".py")]

last_commit_files = set(subprocess.check_output(
    ["git", "diff", "--name-only", "HEAD~1", "HEAD"], encoding="utf-8").splitlines())

new_algorithms = set(current_algorithms) & set(last_commit_files)
conn = Connector()
for el in new_algorithms:
    spec = importlib.util.spec_from_file_location(el[:-3], el)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    classes = [cls for cls_name, cls in inspect.getmembers(module, inspect.isclass)]
    new_algorithm = None
    for cl in classes:
        if el[:-3] in str(cl):
            new_algorithm = cl()

    for el1 in conn.algorithms:
        if type(new_algorithm).__name__ == type(el1[2]).__name__:
            conn.algorithm = el1
            break
    if conn.algorithm is None:
        print("new algorithm wasn't added to Connector!")
        exit()
    test_file_name = "Figure_5.png"
    test_file_path = "algorithms_history/"+test_file_name
    with open(test_file_path, "rb") as file:
        file_bytes = file.read()

    errors, encrypted_files = conn.encrypt_files([[test_file_name, file_bytes]], '')
    if errors:
        print(errors)
        exit()
    encrypted_data = encrypted_files[0][1]

    encrypted_file_path = "algorithms_history/"+type(new_algorithm).__name__+".bin"
    os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)
    subprocess.run(["git", "add", encrypted_file_path])
    subprocess.run(["git", "commit", "-m", f"Added encrypted file {encrypted_file_path}"])
    subprocess.run(["git", "push", "origin", "master"])

deleted_files = set(subprocess.check_output(
    ["git", "diff", "--name-only", "--diff-filter=D", "HEAD^", "HEAD"], encoding="utf-8").splitlines())

deleted_algorithms = set(current_algorithms) & set(deleted_files)
for el in deleted_algorithms:
    file_path_to_del = "algorithms_history/"+el[:-3]+".bin"
    if os.path.exists(file_path_to_del):
        os.remove(file_path_to_del)
        print(f"Removed {file_path_to_del} due to missing algorithm.")



