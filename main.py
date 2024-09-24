import socket
import threading
import tkinter as tk
from tkinter import messagebox
import webbrowser
from tkinter import ttk

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_port(ip, port, open_ports, ports_listbox):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                ports_listbox.insert(tk.END, port)  # 立即更新列表框
        except:
            pass

def start_scan(ip, port_range, result_var, ports_listbox, open_all_button, count_var):
    open_ports = []
    threads = []
    start_port, end_port = port_range

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports, ports_listbox))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports.sort()

    # 更新端口数量显示
    count_var.set(f"数量: {len(open_ports)}")

    if open_ports:
        open_all_button.config(state=tk.NORMAL)
    else:
        open_all_button.config(state=tk.DISABLED)

    # 扫描结束后显示“扫描完毕”
    result_var.set("扫描完毕")

def open_selected_ports(ip, ports_listbox):
    selected_ports = ports_listbox.curselection()
    for index in selected_ports:
        port = ports_listbox.get(index)
        webbrowser.open(f"http://{ip}:{port}")

def open_all_ports(ip, ports_listbox):
    ports = ports_listbox.get(0, tk.END)
    for port in ports:
        webbrowser.open(f"http://{ip}:{port}")

def invert_selection(ports_listbox):
    selected_indices = set(ports_listbox.curselection())
    all_indices = set(range(ports_listbox.size()))
    new_selection = all_indices - selected_indices
    ports_listbox.selection_clear(0, tk.END)
    for index in new_selection:
        ports_listbox.selection_set(index)

def deselect_all(ports_listbox):
    ports_listbox.selection_clear(0, tk.END)

def sort_ports(ports_listbox, ascending=True):
    ports = list(ports_listbox.get(0, tk.END))
    ports.sort(reverse=not ascending)
    ports_listbox.delete(0, tk.END)
    for port in ports:
        ports_listbox.insert(tk.END, port)

def main():
    root = tk.Tk()
    root.title("端口扫描器")
    root.geometry("600x800")
    root.minsize(500, 600)
    root.configure(bg="#F0F4F8")  # 清新明亮的背景色

    # 设置高DPI支持
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    style = ttk.Style()
    style.theme_use('clam')  # 使用clam主题
    style.configure("TFrame", background="#F0F4F8")
    style.configure("TLabel", background="#F0F4F8", foreground="#333333", font=("Segoe UI", 11))
    style.configure("TButton", background="#4CAF50", foreground="#FFFFFF", font=("Segoe UI", 10, "bold"))
    style.map("TButton",
              background=[('active', '#45A049')],
              foreground=[('active', '#FFFFFF')])
    style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#333333", font=("Segoe UI", 11))
    style.configure("TScrollbar", background="#4CAF50")
    style.configure("Listbox", background="#FFFFFF", foreground="#333333", selectbackground="#81C784", selectforeground="#FFFFFF", font=("Segoe UI", 11))
    style.configure("TLabelframe.Label", font=("Segoe UI", 13, "bold"))  # 设置标签框标题字体

    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # 输入部分
    input_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="15")
    input_frame.pack(fill=tk.X, padx=10, pady=10)

    ttk.Label(input_frame, text="域名或IP地址:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
    address_entry = ttk.Entry(input_frame, width=35)
    address_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')

    ttk.Label(input_frame, text="起始端口:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
    start_port_entry = ttk.Entry(input_frame, width=15)
    start_port_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')
    start_port_entry.insert(0, "1")  # 设置起始端口默认值为1

    ttk.Label(input_frame, text="结束端口:").grid(row=2, column=0, padx=10, pady=10, sticky='e')
    end_port_entry = ttk.Entry(input_frame, width=15)
    end_port_entry.grid(row=2, column=1, padx=10, pady=10, sticky='w')
    end_port_entry.insert(0, "65535")  # 设置结束端口默认值为65535

    # 结果显示
    result_var = tk.StringVar()
    result_label = ttk.Label(main_frame, textvariable=result_var)
    result_label.pack(fill=tk.X, padx=20, pady=10)

    # 定义一个StringVar来保存IP地址，使其在整个main函数中可用
    ip_var = tk.StringVar()

    def on_scan():
        address = address_entry.get().strip()
        start_port = start_port_entry.get().strip()
        end_port = end_port_entry.get().strip()

        if not address or not start_port or not end_port:
            messagebox.showerror("错误", "请填写所有字段")
            return

        try:
            start_port_int = int(start_port)
            end_port_int = int(end_port)
            if not (1 <= start_port_int <= 65535 and 1 <= end_port_int <= 65535):
                raise ValueError
            if start_port_int > end_port_int:
                raise ValueError
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口号范围（1-65535）")
            return

        ip = address
        if not all(c.isdigit() or c == '.' for c in address):
            resolved_ip = resolve_domain(address)
            if resolved_ip:
                ip = resolved_ip
            else:
                messagebox.showerror("错误", "无法解析域名")
                return

        # 更新ip_var
        ip_var.set(ip)

        result_var.set("正在扫描...")
        open_all_button.config(state=tk.DISABLED)
        ports_listbox.delete(0, tk.END)
        main_frame.update()

        threading.Thread(target=start_scan, args=(ip, (start_port_int, end_port_int), result_var, ports_listbox, open_all_button, count_var), daemon=True).start()

    # 将“开始扫描”按钮放置在“扫描设置”标签和“打开的端口”标签之间
    scan_button = ttk.Button(main_frame, text="开始扫描", command=on_scan)
    scan_button.pack(padx=20, pady=15, fill=tk.X)

    # 端口列表
    listbox_frame = ttk.LabelFrame(main_frame, text="打开的端口", padding="15")
    listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # 添加一个显示端口数量的标签
    count_var = tk.StringVar()
    count_label = ttk.Label(listbox_frame, textvariable=count_var)
    count_label.pack(anchor='w', padx=10, pady=5)

    scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
    ports_listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar.set, bg="#FFFFFF", fg="#333333", selectbackground="#81C784", selectforeground="#FFFFFF", font=("Segoe UI", 11))
    scrollbar.config(command=ports_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    ports_listbox.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

    # 按钮部分
    button_frame = ttk.Frame(main_frame, padding="10")
    button_frame.pack(fill=tk.X, padx=10, pady=10)

    # 使用grid布局将按钮居中显示
    for i in range(5):
        button_frame.columnconfigure(i, weight=1, uniform="group1")

    # 定义一个布尔变量来跟踪当前的排序顺序
    ascending = tk.BooleanVar(value=True)

    # 新增排序按钮
    def toggle_sort():
        sort_ports(ports_listbox, ascending.get())
        ascending.set(not ascending.get())

    sort_button = ttk.Button(button_frame, text="升/降序", command=toggle_sort)
    sort_button.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

    open_all_button = ttk.Button(button_frame, text="打开所有", state=tk.DISABLED, command=lambda: open_all_ports(ip_var.get(), ports_listbox))
    open_all_button.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

    open_selected_button = ttk.Button(button_frame, text="打开选中", command=lambda: open_selected_ports(ip_var.get(), ports_listbox))
    open_selected_button.grid(row=0, column=2, padx=5, pady=5, sticky='ew')

    invert_selection_button = ttk.Button(button_frame, text="反选", command=lambda: invert_selection(ports_listbox))
    invert_selection_button.grid(row=0, column=3, padx=5, pady=5, sticky='ew')

    deselect_button = ttk.Button(button_frame, text="取消选中", command=lambda: deselect_all(ports_listbox))
    deselect_button.grid(row=0, column=4, padx=5, pady=5, sticky='ew')

    root.mainloop()

if __name__ == "__main__":
    main()