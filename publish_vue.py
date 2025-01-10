import os
import tarfile
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import paramiko
import subprocess
from datetime import datetime
import json
import base64
import logging
import time
import socket


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Vue项目自动部署工具")
        
        # 设置窗口大小和位置
        window_width = 800
        window_height = 700
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # 设置主题颜色
        self.colors = {
            'primary': '#1976D2',
            'secondary': '#424242',
            'success': '#4CAF50',
            'warning': '#FFC107',
            'error': '#F44336',
            'background': '#F5F5F5',
            'surface': '#FFFFFF'
        }
        
        # 设置字体
        self.fonts = {
            'title': ('Helvetica', 20, 'bold'),
            'subtitle': ('Helvetica', 12, 'bold'),
            'body': ('Helvetica', 10),
            'button': ('Helvetica', 10, 'bold')
        }
        
        # 设置窗口背景色
        self.root.configure(bg=self.colors['background'])

        # 配置日志记录
        log_file = 'deployment_log.txt'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        # 使用 FileHandler 确保使用 UTF-8 编码
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        logging.getLogger().addHandler(handler)

        # 使用 StringVar 保存输入内容
        self.local_project_path = tk.StringVar()
        self.new_project_name = tk.StringVar()
        self.server_address = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.remote_path = tk.StringVar()
        self.port = tk.StringVar(value="22")  # 默认端口22

        # 添加新的状态变量
        self.is_deploying = False
        self.deployment_history = []
        self.last_deployment = None

        self.create_widgets()
        self.load_parameters()

    def create_widgets(self):
        # 创建主框架并设置样式
        self.main_frame = tk.Frame(self.root, bg=self.colors['background'])
        self.main_frame.pack(padx=20, pady=20, fill='both', expand=True)
        
        # 添加标题
        title_frame = tk.Frame(self.main_frame, bg=self.colors['background'])
        title_frame.pack(fill='x', pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="Vue项目自动部署工具",
            font=self.fonts['title'],
            fg=self.colors['primary'],
            bg=self.colors['background']
        )
        title_label.pack()
        
        # 创建配置区域
        config_frame = tk.LabelFrame(
            self.main_frame, 
            text="部署配置",
            font=self.fonts['subtitle'],
            bg=self.colors['surface'],
            fg=self.colors['secondary'],
            padx=15,
            pady=10
        )
        config_frame.pack(fill="x", pady=(0, 20))
        
        # 创建输入框和按钮
        self.create_input_fields(config_frame)
        
        # 添加按钮区域
        self.create_button_area()
        
        # 创建日志区域
        self.create_log_area()

    def create_input_fields(self, parent):
        fields = [
            ("本地项目路径", self.local_project_path, self.browse_directory),
            ("新项目名称", self.new_project_name),
            ("服务器地址", self.server_address),
            ("端口号", self.port),
            ("用户名", self.username),
            ("密码", self.password, None, "*"),
            ("远程路径", self.remote_path, self.browse_remote_directory)
        ]
        
        for field in fields:
            self.create_input_field(parent, *field)

    def create_input_field(self, frame, label_text, variable, command=None, show=None):
        field_frame = tk.Frame(frame, bg=self.colors['surface'])
        field_frame.pack(fill="x", pady=5)
        
        label = tk.Label(
            field_frame,
            text=label_text,
            font=self.fonts['body'],
            width=15,
            anchor="w",
            bg=self.colors['surface'],
            fg=self.colors['secondary']
        )
        label.pack(side=tk.LEFT, padx=5)
        
        entry = tk.Entry(
            field_frame,
            textvariable=variable,
            font=self.fonts['body'],
            width=40,
            show=show,
            relief='solid',
            bd=1
        )
        entry.pack(side=tk.LEFT, padx=5)
        
        if command:
            button = tk.Button(
                field_frame,
                text="浏览" if label_text == "本地项目路径" else "选择目录",
                command=command,
                font=self.fonts['button'],
                width=10,
                relief='solid',
                bg=self.colors['primary'],
                fg='white',
                cursor='hand2'
            )
            button.pack(side=tk.LEFT, padx=5)

    def create_button_area(self):
        button_frame = tk.Frame(self.main_frame, bg=self.colors['background'])
        button_frame.pack(pady=10)
        
        self.deploy_button = tk.Button(
            button_frame,
            text="部署项目",
            command=self.start_deployment,
            font=self.fonts['button'],
            width=15,
            bg=self.colors['success'],
            fg='white',
            cursor='hand2',
            relief='solid'
        )
        self.deploy_button.pack(side=tk.LEFT, padx=5)
        
        self.test_conn_button = tk.Button(
            button_frame,
            text="测试连接",
            command=self.test_connection,
            font=self.fonts['button'],
            width=15,
            bg=self.colors['primary'],
            fg='white',
            cursor='hand2',
            relief='solid'
        )
        self.test_conn_button.pack(side=tk.LEFT, padx=5)

    def browse_directory(self):
        # 获取当前路径
        current_path = self.local_project_path.get()
        
        # 如果当前路径存在,则从该路径开始选择
        directory = filedialog.askdirectory(initialdir=current_path if current_path else "/")
        if directory:
            self.local_project_path.set(directory)

    def start_deployment(self):
        """开始部署前的准备工作"""
        if self.is_deploying:
            messagebox.showwarning("警告", "部署正在进行中...")
            return
            
        if not self.validate_inputs():
            return
            
        self.is_deploying = True
        self.deploy_button.config(state="disabled")
        self.log_text.delete(1.0, tk.END)
        
        threading.Thread(target=self.deploy_with_progress).start()
        
    def deploy_with_progress(self):
        """带进度显示的部署过程"""
        try:
            start_time = time.time()
            self.deploy()
            end_time = time.time()
            
            # 记录部署历史
            self.deployment_history.append({
                "timestamp": datetime.now(),
                "duration": end_time - start_time,
                "status": "success"
            })
            
        except Exception as e:
            self.log(f"部署过程出错: {str(e)}")
            messagebox.showerror("错误", f"部署失败: {str(e)}")
        finally:
            self.is_deploying = False
            self.deploy_button.config(state="normal")

    def deploy(self):
        local_project_path = self.local_project_path.get()
        new_project_name = self.new_project_name.get()
        host = self.server_address.get()
        username = self.username.get()
        password = self.password.get()
        remote_path = self.remote_path.get()

        self.log("开始打包项目...")
        os.chdir(local_project_path)

        self.run_command("npm run build")

        self.log("开始压缩打包文件...")
        self.compress_project()

        self.log("开始上传包到服务器...")
        if not self.upload_package(host, username, password):
            return

        self.log("开始备份现有项目...")
        if not self.backup_existing_project(host, username, password, remote_path, new_project_name):
            return

        self.log("开始在服务器上解压和重命名...")
        if self.execute_remote_commands(new_project_name, host, username, password, remote_path):
            self.log("解压和重命名成功。")
            self.log("项目部署完成！")
            messagebox.showinfo("成功", "项目部署完成！")
        else:
            self.log("解压和重命名失败。")

        self.save_parameters()

    def compress_project(self):
        with tarfile.open('project.tar.gz', 'w:gz') as tar:
            tar.add('dist', arcname=os.path.basename('dist'))
        self.log("压缩完成。")

    def log(self, message, level="info"):
        """增强的日志记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level.upper()}] {message}"
        
        # 根据日志级别设置颜色
        tag = None
        if level == "error":
            tag = "error"
            self.log_text.tag_config("error", foreground="red")
        elif level == "warning":
            tag = "warning"
            self.log_text.tag_config("warning", foreground="orange")
        elif level == "success":
            tag = "success"
            self.log_text.tag_config("success", foreground="green")
            
        # 在窗口中显示日志
        self.log_text.insert(tk.END, formatted_message + '\n', tag)
        self.log_text.yview(tk.END)
        
        # 记录到日志文件
        logging.log(
            logging.ERROR if level == "error"
            else logging.WARNING if level == "warning"
            else logging.INFO,
            message
        )

    def run_command(self, command):
        """改进的命令执行函数"""
        self.log(f"执行命令: {command}")
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        output = []
        for stdout_line in iter(process.stdout.readline, ""):
            line = stdout_line.strip()
            output.append(line)
            self.log(line)

        process.stdout.close()
        stderr_output = process.stderr.read()
        process.stderr.close()
        process.wait()

        if process.returncode != 0:
            self.log(f"命令 {command} 执行失败，返回码: {process.returncode}", "error")
            if stderr_output:
                self.log(f"错误: {stderr_output.strip()}", "error")
            return False

        # 检查构建警告
        if command == "npm run build":
            return self.check_build_warnings('\n'.join(output))
            
        return True

    def check_build_warnings(self, output):
        """检查构建警告和错误"""
        warnings = []
        errors = []
        
        lines = output.split('\n')
        for line in lines:
            if 'WARNING' in line:
                warnings.append(line)
            elif 'ERROR' in line or 'error' in line.lower():
                errors.append(line)
                
        if errors:
            self.log("构建过程中发现错误:", "error")
            for error in errors:
                self.log(error, "error")
                
        if warnings:
            self.log("构建过程中发现警告:", "warning")
            for warning in warnings:
                self.log(warning, "warning")
                
        return len(errors) == 0  # 如果没有错误返回True

    def upload_package(self, host, username, password):
        try:
            transport = paramiko.Transport((host, 22))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.put('project.tar.gz', 'project.tar.gz')
            sftp.close()
            transport.close()
            self.log("上传成功。")
            return True
        except Exception as e:
            self.log(f"上传失败: {str(e)}")
            return False

    def backup_existing_project(self, host, username, password, remote_path, new_project_name):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_name = f"{new_project_name}_backup_{timestamp}"

            commands = f"""
if [ -d '{remote_path}/{new_project_name}/dist' ]; then
    mv '{remote_path}/{new_project_name}' '{remote_path}/{backup_name}';
fi
"""
            stdin, stdout, stderr = ssh.exec_command(commands)
            for line in stdout:
                self.log(line.strip())
            for line in stderr:
                self.log(f"错误: {line.strip()}")
            ssh.close()
            self.log("备份成功。")
            return True
        except Exception as e:
            self.log(f"备份失败: {str(e)}")
            return False

    def execute_remote_commands(self, new_project_name, host, username, password, remote_path):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password)

            commands = f"""
set -e
if [ -d '{remote_path}/{new_project_name}/dist' ]; then
    rm -rf '{remote_path}/{new_project_name}/dist'
fi
cd {remote_path}
tar -xzf ~/project.tar.gz
if [ ! -d "dist" ]; then
    echo "解压失败：dist 目录不存在"
    exit 1
fi
if [ -d "{new_project_name}" ]; then
    rm -rf "{new_project_name}"
fi
mv dist "{new_project_name}"
if [ ! -d "{new_project_name}" ]; then
    echo "移动失败：新项目目录不存在"
    exit 1
fi
echo "部署完成"
"""
            stdin, stdout, stderr = ssh.exec_command(commands)
            
            # 等待命令执行完成
            exit_status = stdout.channel.recv_exit_status()
            
            # 收集所有输出
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            
            if exit_status != 0:
                self.log(f"命令执行失败，退出码：{exit_status}")
                if err:
                    self.log(f"错误输出：{err}")
                return False
                
            if out:
                self.log(out)
            
            # 验证部署结果
            verify_cmd = f"test -d '{remote_path}/{new_project_name}' && echo 'OK'"
            stdin, stdout, stderr = ssh.exec_command(verify_cmd)
            result = stdout.read().decode().strip()
            
            if result != 'OK':
                self.log("部署验证失败：目标目录不存在")
                return False

            ssh.close()
            self.log("解压和重命名成功。")
            return True
        except Exception as e:
            self.log(f"解压和重命名失败: {str(e)}")
            return False

    def load_parameters(self):
        """增强的配置加载"""
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                # 加载基本配置
                self.local_project_path.set(config.get('local_project_path', ''))
                self.new_project_name.set(config.get('new_project_name', ''))
                self.server_address.set(config.get('server_address', ''))
                self.username.set(config.get('username', ''))
                self.password.set(self.decrypt_password(config.get('password', '')))
                self.remote_path.set(config.get('remote_path', ''))
                
                # 加载部署历史并转换回datetime对象
                self.deployment_history = []
                for record in config.get('deployment_history', []):
                    self.deployment_history.append({
                        'timestamp': datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S'),
                        'duration': record['duration'],
                        'status': record['status']
                    })
                    
                self.log("配置加载成功", "success")
        except Exception as e:
            self.log(f"加载配置失败: {str(e)}", "error")
            
    def save_parameters(self):
        """增强的配置保存"""
        try:
            # 转换部署历史中的datetime对象为字符串
            deployment_history = []
            for record in self.deployment_history[-10:]:  # 只保存最近10次部署记录
                deployment_history.append({
                    'timestamp': record['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': round(record['duration'], 2),
                    'status': record['status']
                })

            config = {
                'local_project_path': self.local_project_path.get(),
                'new_project_name': self.new_project_name.get(),
                'server_address': self.server_address.get(),
                'username': self.username.get(),
                'password': self.encrypt_password(self.password.get()),
                'remote_path': self.remote_path.get(),
                'deployment_history': deployment_history
            }
            
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                
            self.log("配置保存成功", "success")
        except Exception as e:
            self.log(f"保存配置失败: {str(e)}", "error")

    def encrypt_password(self, password):
        return base64.b64encode(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return base64.b64decode(encrypted_password.encode()).decode()

    def test_connection(self):
        """测试服务器连接"""
        try:
            host = self.server_address.get()
            username = self.username.get()
            password = self.password.get()
            port = int(self.port.get())
            
            # 设置超时时间为5秒
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                host, 
                port=port,
                username=username, 
                password=password,
                timeout=5,  # 添加5秒超时
                banner_timeout=5  # banner获取超时也设为5秒
            )
            ssh.close()
            
            messagebox.showinfo("成功", "服务器连接测试成功!")
        except socket.timeout:
            messagebox.showerror("错误", "连接超时，请检查服务器地址是否正确!")
        except paramiko.ssh_exception.AuthenticationException:
            messagebox.showerror("错误", "认证失败，请检查用户名和密码!")
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {str(e)}")
            
    def validate_inputs(self):
        """验证输入参数"""
        required_fields = {
            "本地项目路径": self.local_project_path.get(),
            "新项目名称": self.new_project_name.get(),
            "服务器地址": self.server_address.get(),
            "用户名": self.username.get(),
            "密码": self.password.get(),
            "远程路径": self.remote_path.get(),
            "端口号": self.port.get()
        }
        
        for field, value in required_fields.items():
            if not value:
                messagebox.showerror("错误", f"{field}不能为空!")
                return False
            
        # 验证端口号是否为有效数字
        try:
            port = int(self.port.get())
            if port <= 0 or port > 65535:
                messagebox.showerror("错误", "端口号必须在1-65535之间!")
                return False
        except ValueError:
            messagebox.showerror("错误", "端口号必须是有效的数字!")
            return False
        
        return True

    def browse_remote_directory(self):
        try:
            host = self.server_address.get()
            username = self.username.get()
            password = self.password.get()
            port = int(self.port.get())
            
            if not all([host, username, password]):
                messagebox.showerror("错误", "请先填写服务器地址、用户名和密码!")
                return
                
            # 创建SSH连接
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=5,
                banner_timeout=5
            )
            
            # 获取当前选择的远程路径
            current_remote_path = self.remote_path.get()
            
            # 创建目录选择对话框,并传入当前路径
            dialog = RemoteDirectoryDialog(self.root, ssh, current_remote_path)
            selected_path = dialog.show()
            
            if selected_path:
                self.remote_path.set(selected_path)
                
            ssh.close()
            
        except socket.timeout:
            messagebox.showerror("错误", "连接超时，请检查服务器地址是否正确!")
        except paramiko.ssh_exception.AuthenticationException:
            messagebox.showerror("错误", "认证失败，请检查用户名和密码!")
        except Exception as e:
            messagebox.showerror("错误", f"连接服务器失败: {str(e)}")

    def create_log_area(self):
        # 创建日志区域
        log_frame = tk.LabelFrame(
            self.main_frame,
            text="部署日志",
            font=self.fonts['subtitle'],
            bg=self.colors['surface'],
            fg=self.colors['secondary'],
            padx=15,
            pady=10
        )
        log_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # 创建日志文本框
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=self.fonts['body'],
            bg=self.colors['surface'],
            height=15,
            relief='solid',
            bd=1
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 配置日志文本标签样式
        self.log_text.tag_config("error", foreground=self.colors['error'])
        self.log_text.tag_config("warning", foreground=self.colors['warning'])
        self.log_text.tag_config("success", foreground=self.colors['success'])

    def create_connection_frame(self):
        # ... 其他代码 ...
        
        # 添加端口号输入框
        tk.Label(
            connection_frame,
            text="端口号:",
            font=self.fonts['body'],
            bg=self.colors['surface']
        ).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        
        port_entry = tk.Entry(
            connection_frame,
            textvariable=self.port,
            font=self.fonts['body'],
            width=30
        )
        port_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

class RemoteDirectoryDialog:
    def __init__(self, parent, ssh, initial_path="/"):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("选择远程目录")
        
        # 设置对话框大小和位置
        dialog_width = 600
        dialog_height = 400
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - dialog_width) // 2
        y = (screen_height - dialog_height) // 2
        self.dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        # 定义颜色和字体
        self.colors = {
            'primary': '#1976D2',
            'secondary': '#424242',
            'success': '#4CAF50',
            'warning': '#FFC107',
            'error': '#F44336',
            'background': '#F5F5F5',
            'surface': '#FFFFFF'
        }
        
        self.fonts = {
            'title': ('Helvetica', 16, 'bold'),
            'subtitle': ('Helvetica', 12, 'bold'),
            'body': ('Helvetica', 10),
            'button': ('Helvetica', 10, 'bold')
        }
        
        self.dialog.configure(bg=self.colors['background'])
        self.ssh = ssh
        # 使用传入的初始路径
        self.current_path = initial_path if initial_path else "/"
        self.result = None
        
        self.create_widgets()
        self.load_directory()

    def create_widgets(self):
        # 当前路径显示
        path_frame = tk.Frame(self.dialog, bg=self.colors['background'])
        path_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(
            path_frame,
            text="当前路径:",
            font=self.fonts['subtitle'],
            bg=self.colors['background'],
            fg=self.colors['secondary']
        ).pack(side=tk.LEFT)
        
        self.path_label = tk.Label(
            path_frame,
            text="/",
            font=self.fonts['body'],
            bg=self.colors['background'],
            fg=self.colors['primary']
        )
        self.path_label.pack(side=tk.LEFT, fill="x", expand=True)
        
        # 目录列表
        list_frame = tk.Frame(self.dialog, bg=self.colors['surface'])
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.dir_listbox = tk.Listbox(
            list_frame,
            font=self.fonts['body'],
            selectmode=tk.SINGLE,
            relief='solid',
            bd=1
        )
        self.dir_listbox.pack(side=tk.LEFT, fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.dir_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.dir_listbox.yview)
        
        # 绑定双击事件
        self.dir_listbox.bind("<Double-Button-1>", self.on_double_click)
        
        # 按钮区域
        button_frame = tk.Frame(self.dialog, bg=self.colors['background'])
        button_frame.pack(fill="x", padx=10, pady=10)
        
        buttons = [
            ("选择当前目录", self.on_select, self.colors['success']),
            ("上级目录", self.go_parent, self.colors['primary']),
            ("取消", self.on_cancel, self.colors['secondary'])
        ]
        
        for text, command, color in buttons:
            tk.Button(
                button_frame,
                text=text,
                command=command,
                font=self.fonts['button'],
                bg=color,
                fg='white',
                width=12,
                cursor='hand2',
                relief='solid'
            ).pack(side=tk.LEFT, padx=5)

    def load_directory(self):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(f'ls -la "{self.current_path}"')
            self.dir_listbox.delete(0, tk.END)
            
            # 添加特殊目录
            if self.current_path != "/":
                self.dir_listbox.insert(tk.END, "..")
            
            for line in stdout:
                if line.startswith('d'):  # 只显示目录
                    name = line.split()[-1]
                    if name not in ['.', '..']:
                        self.dir_listbox.insert(tk.END, name)
                        
            self.path_label.config(text=self.current_path)
            
        except Exception as e:
            messagebox.showerror("错误", f"读取目录失败: {str(e)}")
            
    def on_double_click(self, event):
        selection = self.dir_listbox.curselection()
        if selection:
            dirname = self.dir_listbox.get(selection[0])
            if dirname == "..":
                self.go_parent()
            else:
                new_path = os.path.join(self.current_path, dirname).replace("\\", "/")
                if new_path == "//":
                    new_path = "/"
                self.current_path = new_path
                self.load_directory()
            
    def go_parent(self):
        if self.current_path != "/":
            self.current_path = os.path.dirname(self.current_path)
            if not self.current_path:
                self.current_path = "/"
            self.load_directory()
            
    def on_select(self):
        self.result = self.current_path
        self.dialog.destroy()
        
    def on_cancel(self):
        self.dialog.destroy()
        
    def show(self):
        self.dialog.transient(self.dialog.master)
        self.dialog.grab_set()
        self.dialog.wait_window()
        return self.result


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()