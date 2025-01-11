import os
import tarfile
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import paramiko
import subprocess
from datetime import datetime
import json
import base64
import logging
import time
import socket
import csv
from cryptography.fernet import Fernet


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Vue项目自动部署工具")

        # 获取工具所在目录的绝对路径
        self.tool_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 设置配置文件路径
        self.config_file = os.path.join(self.tool_dir, 'config.json')
        self.history_file = os.path.join(self.tool_dir, 'deployment_history.json')
        self.log_file = os.path.join(self.tool_dir, 'deployment_log.txt')
        self.log_dir = os.path.join(self.tool_dir, 'logs')

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

        # 先创建界面
        self.create_widgets()
        
        # 然后初始化文件和目录
        self.init_files_and_directories()
        
        # 最后加载参数
        self.load_parameters()

    def init_files_and_directories(self):
        """初始化必要的文件和目录"""
        try:
            # 确保配置文件存在
            if not os.path.exists(self.config_file):
                default_config = {
                    'local_project_path': '',
                    'new_project_name': '',
                    'server_address': '',
                    'username': '',
                    'password': '',
                    'remote_path': '',
                    'servers': []
                }
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, ensure_ascii=False, indent=2)
                self.log("创建默认配置文件", "success")

            # 确保部署历史文件存在
            if not os.path.exists(self.history_file):
                with open(self.history_file, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=2)
                self.log("创建部署历史文件", "success")

            # 确保日志目录存在
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
                self.log("创建日志目录", "success")

        except Exception as e:
            messagebox.showerror("错误", f"初始化文件和目录失败: {str(e)}")

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

        # 创建按钮并保存为实例属性
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

        self.history_button = tk.Button(
            button_frame,
            text="部署历史",
            command=self.show_deployment_history,
            font=self.fonts['button'],
            width=15,
            bg=self.colors['primary'],
            fg='white',
            cursor='hand2',
            relief='solid'
        )
        self.history_button.pack(side=tk.LEFT, padx=5)

        self.server_button = tk.Button(
            button_frame,
            text="服务器管理",
            command=self.show_server_manager,
            font=self.fonts['button'],
            width=15,
            bg=self.colors['primary'],
            fg='white',
            cursor='hand2',
            relief='solid'
        )
        self.server_button.pack(side=tk.LEFT, padx=5)

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
        self.deploy_lock = threading.Lock()
        with self.deploy_lock:
            try:
                start_time = time.time()
                self.deploy()
                end_time = time.time()

                # 记录部署历史到单独的文件
                deployment_record = {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "duration": end_time - start_time,
                    "status": "success",
                    "project_name": self.new_project_name.get(),
                    "server": self.server_address.get()
                }

                # 保存部署历史
                self.save_deployment_history(deployment_record)

            except Exception as e:
                self.log(f"部署过程出错: {str(e)}")
                messagebox.showerror("错误", f"部署失败: {str(e)}")
            finally:
                self.is_deploying = False
                self.deploy_button.config(state="normal")

    def deploy(self):
        try:
            # 保存当前工作目录
            original_dir = os.getcwd()
            
            local_project_path = self.local_project_path.get()
            new_project_name = self.new_project_name.get()
            host = self.server_address.get()
            username = self.username.get()
            password = self.password.get()
            remote_path = self.remote_path.get()

            self.log("开始打包项目...")
            
            try:
                # 切换到Vue项目目录
                os.chdir(local_project_path)

                # 执行构建
                if not self.run_command("npm run build"):
                    return False

                # 压缩dist目录
                if not self.compress_project():
                    return False

                # 获取压缩文件的完整路径
                tar_path = os.path.join(local_project_path, 'project.tar.gz')

                self.log("开始上传包到服务器...")
                if not self.upload_package(host, username, password, tar_path):
                    return False

                self.log("开始备份现有项目...")
                if not self.backup_existing_project(host, username, password, remote_path, new_project_name):
                    return False

                self.log("开始在服务器上解压和重命名...")
                if self.execute_remote_commands(new_project_name, host, username, password, remote_path):
                    self.log("解压和重命名成功。")
                    self.log("项目部署完成！")
                    messagebox.showinfo("成功", "项目部署完成！")
                else:
                    self.log("解压和重命名失败。")

                self.save_parameters()

            except Exception as e:
                self.log(f"部署失败: {str(e)}", "error")
                return False
            finally:
                # 清理临时文件
                if os.path.exists('project.tar.gz'):
                    os.remove('project.tar.gz')
                # 确保最后切回工具目录
                os.chdir(original_dir)

        except Exception as e:
            self.log(f"部署失败: {str(e)}", "error")
            return False

    def compress_project(self):
        """只压缩 dist 目录的内容"""
        try:
            # 确保只压缩 dist 目录
            if not os.path.exists('dist'):
                self.log("dist 目录不存在，请先构建项目", "error")
                return False
                
            with tarfile.open('project.tar.gz', 'w:gz') as tar:
                # 直接进入dist目录打包内容，不包含dist目录本身
                for item in os.listdir('dist'):
                    item_path = os.path.join('dist', item)
                    arcname = item  # 直接使用文件名，不包含dist目录
                    self.log(f"正在压缩: {item_path}")
                    tar.add(item_path, arcname=arcname)
                
            self.log("压缩完成。")
            return True
            
        except Exception as e:
            self.log(f"压缩失败: {str(e)}", "error")
            return False

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

    def upload_package(self, host, username, password, local_file):
        """上传打包文件到服务器"""
        try:
            transport = paramiko.Transport((host, 22))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            # 上传到用户主目录
            remote_file = 'project.tar.gz'
            sftp.put(local_file, remote_file)
            
            sftp.close()
            transport.close()
            self.log("上传成功。")
            return True
        except Exception as e:
            self.log(f"上传失败: {str(e)}")
            return False

    def backup_existing_project(self, host, username, password, remote_path, project_name):
        """备份现有项目"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password)
            
            # 使用正斜杠，确保路径格式正确
            backup_time = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_dir = f"{remote_path}/backups"
            backup_path = f"{backup_dir}/{project_name}_backup_{backup_time}"
            
            # 创建备份命令
            commands = f"""
mkdir -p {backup_dir}
if [ -d "{remote_path}/{project_name}" ]; then
    cp -r "{remote_path}/{project_name}" "{backup_path}" && echo "备份成功" || echo "备份失败"
else
    echo "目录不存在"
fi
"""
            stdin, stdout, stderr = ssh.exec_command(commands)
            result = stdout.read().decode().strip()
            
            if "备份成功" in result:
                self.log(f"项目已备份到: {backup_path}")
                return True
            else:
                self.log(f"备份失败或目录不存在: {result}", "error")
                return False
            
        except Exception as e:
            self.log(f"备份失败: {str(e)}", "error")
            return False
        finally:
            if ssh:
                ssh.close()

    def execute_remote_commands(self, new_project_name, host, username, password, remote_path):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password)

            commands = f"""
set -e
cd {remote_path}
# 创建临时目录
mkdir -p temp_deploy

# 移动并解压文件
mv ~/project.tar.gz temp_deploy/
cd temp_deploy
tar -xzf project.tar.gz

# 如果目标目录已存在，则删除
if [ -d "../{new_project_name}" ]; then
    rm -rf "../{new_project_name}"
fi

# 创建新目录并移动文件
mkdir -p "../{new_project_name}"
mv * "../{new_project_name}/" 2>/dev/null || true  # 忽略 project.tar.gz 的移动错误

# 清理临时目录和文件
cd ..
rm -rf temp_deploy
rm -f ~/project.tar.gz  # 删除用户主目录下的压缩包

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
        finally:
            if ssh:
                ssh.close()

    def load_parameters(self):
        """增强的配置加载"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
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
            # 确保配置目录存在
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            # 读取现有配置（如果存在）
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            # 更新基本配置
            config.update({
                'local_project_path': self.local_project_path.get(),
                'new_project_name': self.new_project_name.get(),
                'server_address': self.server_address.get(),
                'username': self.username.get(),
                'password': self.encrypt_password(self.password.get()),
                'remote_path': self.remote_path.get(),
            })

            # 确保存在servers数组
            if 'servers' not in config:
                config['servers'] = []

            # 添加当前服务器配置到servers列表（如果不存在）
            current_server = {
                'name': f"{self.server_address.get()}_{self.username.get()}",  # 使用地址和用户名组合作为服务器名称
                'address': self.server_address.get(),
                'port': self.port.get(),
                'username': self.username.get(),
                'password': self.encrypt_password(self.password.get()),
                'remote_path': self.remote_path.get()
            }

            # 检查是否已存在相同的服务器配置
            server_exists = False
            for i, server in enumerate(config['servers']):
                if server['address'] == current_server['address'] and server['username'] == current_server['username']:
                    config['servers'][i] = current_server
                    server_exists = True
                    break

            if not server_exists:
                config['servers'].append(current_server)

            # 保存配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
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

            if not all([host, username, password]):
                messagebox.showerror("错误", "请先填写服务器地址、用户名和密码!")
                return

            # 创建并显示测试连接对话框
            TestConnectionDialog(
                self.root,
                host,
                port,
                username,
                password
            )
        except Exception as e:
            messagebox.showerror("错误", f"测试连接失败: {str(e)}")

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

        # 添加更多验证
        def is_valid_path(path):
            return os.path.exists(path) and os.path.isdir(path)
        
        def is_valid_project(path):
            return os.path.exists(os.path.join(path, 'package.json'))
        
        if not is_valid_path(self.local_project_path.get()):
            messagebox.showerror("错误", "本地项目路径不存在!")
            return False
        
        if not is_valid_project(self.local_project_path.get()):
            messagebox.showerror("错误", "无效的Vue项目目录!")
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

        # 添加按钮区域
        button_frame = tk.Frame(log_frame, bg=self.colors['surface'])
        button_frame.pack(fill="x", padx=5, pady=5)

        # 添加日志导出功能
        export_button = tk.Button(
            button_frame,
            text="导出日志",
            command=self.export_logs,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        export_button.pack(side=tk.LEFT, padx=5)

        # 添加查看日志按钮
        view_log_button = tk.Button(
            button_frame,
            text="查看日志",
            command=self.show_log_viewer,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        view_log_button.pack(side=tk.LEFT, padx=5)

    def show_log_viewer(self):
        """显示日志查看器"""
        viewer = LogViewer(self.root, self.fonts, self.colors)
        viewer.show()

    def export_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"deployment_log_{timestamp}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("成功", f"日志已导出到 {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"导出日志失败: {str(e)}")

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

    def show_deployment_history(self):
        """显示部署历史记录"""
        history_viewer = DeploymentHistory(self.root, self.fonts, self.colors)
        history_viewer.show()

    def show_server_manager(self):
        """显示服务器管理器"""
        try:
            # 创建服务器管理器时传递 self.root 作为父窗口，同时传递 self 作为应用程序引用
            server_manager = ServerManager(parent_window=self.root, app=self, fonts=self.fonts, colors=self.colors)
            server_manager.show()
        except Exception as e:
            self.log(f"打开服务器管理器失败: {str(e)}", "error")
            messagebox.showerror("错误", f"打开服务器管理器失败: {str(e)}")

    def save_deployment_history(self, record):
        """保存部署历史到单独的文件"""
        try:
            # 读取现有历史记录
            history = []
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            
            # 添加新记录
            history.append(record)
            
            # 保存历史记录
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
                
            self.log("部署历史已保存", "success")
        except Exception as e:
            self.log(f"保存部署历史失败: {str(e)}", "error")


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


class LogViewer:
    def __init__(self, parent, fonts, colors):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("日志查看器")
        
        # 设置窗口大小和位置
        window_width = 1000
        window_height = 600
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")

        self.fonts = fonts
        self.colors = colors
        self.dialog.configure(bg=self.colors['background'])
        
        # 创建工具栏
        self.create_toolbar()
        
        # 创建日志显示区域
        self.create_log_area()
        
        # 创建过滤器区域
        self.create_filter_area()
        
        # 初始化变量
        self.auto_refresh = tk.BooleanVar(value=False)
        self.filter_text = tk.StringVar()
        self.log_level_filter = tk.StringVar(value="ALL")
        
        # 加载日志
        self.load_logs()
        
        # 启动自动刷新
        self.start_auto_refresh()

    def create_toolbar(self):
        toolbar = tk.Frame(self.dialog, bg=self.colors['surface'])
        toolbar.pack(fill="x", padx=10, pady=5)
        
        # 刷新按钮
        refresh_btn = tk.Button(
            toolbar,
            text="刷新",
            command=self.load_logs,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # 自动刷新开关
        auto_refresh_cb = tk.Checkbutton(
            toolbar,
            text="自动刷新",
            variable=self.auto_refresh,
            font=self.fonts['body'],
            bg=self.colors['surface']
        )
        auto_refresh_cb.pack(side=tk.LEFT, padx=5)
        
        # 导出按钮
        export_btn = tk.Button(
            toolbar,
            text="导出日志",
            command=self.export_logs,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # 清空按钮
        clear_btn = tk.Button(
            toolbar,
            text="清空日志",
            command=self.clear_logs,
            font=self.fonts['button'],
            bg=self.colors['warning'],
            fg='white'
        )
        clear_btn.pack(side=tk.LEFT, padx=5)

    def create_filter_area(self):
        filter_frame = tk.Frame(self.dialog, bg=self.colors['surface'])
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        # 搜索框
        tk.Label(
            filter_frame,
            text="搜索:",
            font=self.fonts['body'],
            bg=self.colors['surface']
        ).pack(side=tk.LEFT, padx=5)
        
        search_entry = tk.Entry(
            filter_frame,
            textvariable=self.filter_text,
            font=self.fonts['body'],
            width=40
        )
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', self.apply_filter)
        
        # 日志级别过滤
        tk.Label(
            filter_frame,
            text="日志级别:",
            font=self.fonts['body'],
            bg=self.colors['surface']
        ).pack(side=tk.LEFT, padx=5)
        
        levels = ['ALL', 'INFO', 'WARNING', 'ERROR', 'SUCCESS']
        level_menu = tk.OptionMenu(
            filter_frame,
            self.log_level_filter,
            *levels,
            command=self.apply_filter
        )
        level_menu.config(font=self.fonts['body'])
        level_menu.pack(side=tk.LEFT, padx=5)

    def create_log_area(self):
        # 创建日志文本框
        self.log_text = scrolledtext.ScrolledText(
            self.dialog,
            font=self.fonts['body'],
            bg=self.colors['surface'],
            height=30,
            relief='solid',
            bd=1
        )
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 配置标签样式
        self.log_text.tag_config("error", foreground=self.colors['error'])
        self.log_text.tag_config("warning", foreground=self.colors['warning'])
        self.log_text.tag_config("success", foreground=self.colors['success'])
        self.log_text.tag_config("highlight", background="yellow")

    def load_logs(self):
        try:
            with open('deployment_log.txt', 'r', encoding='utf-8') as f:
                logs = f.readlines()
            
            self.log_text.delete(1.0, tk.END)
            for log in logs:
                self.add_log_line(log.strip())
                
            self.apply_filter()
        except Exception as e:
            messagebox.showerror("错误", f"加载日志失败: {str(e)}")

    def add_log_line(self, line):
        tag = None
        if "ERROR" in line.upper():
            tag = "error"
        elif "WARNING" in line.upper():
            tag = "warning"
        elif "SUCCESS" in line.upper():
            tag = "success"
            
        self.log_text.insert(tk.END, line + '\n', tag)

    def apply_filter(self, event=None):
        # 保存当前位置
        current_pos = self.log_text.yview()
        
        # 获取所有文本
        text = self.log_text.get(1.0, tk.END)
        lines = text.split('\n')
        
        # 清除所有文本和高亮
        self.log_text.delete(1.0, tk.END)
        
        # 应用过滤器
        filter_text = self.filter_text.get().lower()
        level_filter = self.log_level_filter.get()
        
        for line in lines:
            if not line.strip():
                continue
                
            # 检查日志级别
            if level_filter != 'ALL':
                if level_filter.lower() not in line.lower():
                    continue
            
            # 检查搜索文本
            if filter_text:
                if filter_text in line.lower():
                    self.log_text.insert(tk.END, line + '\n')
                    # 高亮匹配文本
                    start_idx = line.lower().find(filter_text)
                    while start_idx != -1:
                        start = f"{self.log_text.index('end-2c').split('.')[0]}.{start_idx}"
                        end = f"{self.log_text.index('end-2c').split('.')[0]}.{start_idx + len(filter_text)}"
                        self.log_text.tag_add("highlight", start, end)
                        start_idx = line.lower().find(filter_text, start_idx + 1)
            else:
                self.log_text.insert(tk.END, line + '\n')
        
        # 恢复滚动位置
        self.log_text.yview_moveto(current_pos[0])

    def export_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"deployment_log_{timestamp}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("成功", f"日志已导出到 {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"导出日志失败: {str(e)}")

    def clear_logs(self):
        if messagebox.askyesno("确认", "确定要清空日志吗？"):
            try:
                with open('deployment_log.txt', 'w', encoding='utf-8') as f:
                    f.write('')
                self.load_logs()
                messagebox.showinfo("成功", "日志已清空")
            except Exception as e:
                messagebox.showerror("错误", f"清空日志失败: {str(e)}")

    def start_auto_refresh(self):
        def refresh_loop():
            if self.auto_refresh.get():
                self.load_logs()
            self.dialog.after(5000, refresh_loop)  # 每5秒刷新一次
        refresh_loop()

    def show(self):
        self.dialog.transient(self.dialog.master)
        self.dialog.grab_set()
        self.dialog.wait_window()


class DeploymentHistory:
    def __init__(self, parent, fonts, colors):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("部署历史")
        
        # 设置窗口大小和位置
        window_width = 800
        window_height = 500
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")

        self.fonts = fonts
        self.colors = colors
        self.dialog.configure(bg=self.colors['background'])
        
        self.create_widgets()
        self.load_history()

    def create_widgets(self):
        # 创建表格
        columns = ('时间', '状态', '耗时', '项目名称', '服务器')
        self.tree = ttk.Treeview(self.dialog, columns=columns, show='headings')
        
        # 设置列标题
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        
        self.tree.pack(fill='both', expand=True, padx=10, pady=5)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(self.dialog, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 添加按钮区域
        button_frame = tk.Frame(self.dialog, bg=self.colors['background'])
        button_frame.pack(fill='x', padx=10, pady=5)
        
        # 刷新按钮
        refresh_btn = tk.Button(
            button_frame,
            text="刷新",
            command=self.load_history,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # 回滚按钮
        rollback_btn = tk.Button(
            button_frame,
            text="回滚到选中版本",
            command=self.rollback,
            font=self.fonts['button'],
            bg=self.colors['warning'],
            fg='white'
        )
        rollback_btn.pack(side=tk.LEFT, padx=5)
        
        # 导出按钮
        export_btn = tk.Button(
            button_frame,
            text="导出历史记录",
            command=self.export_history,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        )
        export_btn.pack(side=tk.LEFT, padx=5)

    def load_history(self):
        # 清空现有数据
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        try:
            history_file = 'deployment_history.json'
            if os.path.exists(history_file):
                with open(history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
                    
                    for record in history:
                        # 格式化时间和耗时
                        timestamp = record['timestamp']
                        duration = f"{record['duration']:.2f}秒"
                        
                        # 获取状态图标
                        status = record['status']
                        status_text = "✓" if status == "success" else "✗"
                        
                        # 插入数据
                        self.tree.insert('', 0, values=(
                            timestamp,
                            status_text,
                            duration,
                            record.get('project_name', '-'),
                            record.get('server', '-')
                        ))
        except Exception as e:
            messagebox.showerror("错误", f"加载部署历史失败: {str(e)}")

    def rollback(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要回滚的版本")
            return
            
        item = self.tree.item(selection[0])
        timestamp = item['values'][0]
        
        if messagebox.askyesno("确认", f"确定要回滚到 {timestamp} 的版本吗？"):
            # TODO: 实现回滚逻辑
            messagebox.showinfo("提示", "回滚功能正在开发中...")

    def export_history(self):
        """导出部署历史到选择的目录"""
        try:
            # 让用户选择保存目录和文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"deployment_history_{timestamp}.csv"
            
            file_path = filedialog.asksaveasfilename(
                initialfile=default_filename,
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if not file_path:  # 用户取消选择
                return
                
            with open(file_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                # 写入表头
                columns = ['时间', '状态', '耗时', '项目名称', '服务器']
                writer.writerow(columns)
                
                # 写入数据
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    writer.writerow(values)
                    
            messagebox.showinfo("成功", f"部署历史已导出到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出历史记录失败: {str(e)}")

    def show(self):
        self.dialog.transient(self.dialog.master)
        self.dialog.grab_set()
        self.dialog.wait_window()


class ServerManager:
    def __init__(self, parent_window, app, fonts, colors):
        """
        初始化服务器管理器
        @param parent_window: Tk窗口对象(self.root)
        @param app: App类实例(self)
        @param fonts: 字体配置
        @param colors: 颜色配置
        """
        self.dialog = tk.Toplevel(parent_window)
        self.dialog.title("服务器管理")
        
        # 设置窗口大小和位置
        window_width = 600
        window_height = 400
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # 保存应用程序引用
        self.app = app
        self.fonts = fonts
        self.colors = colors
        self.dialog.configure(bg=self.colors['background'])
        
        # 创建界面元素
        self.create_widgets()
        
        # 加载服务器列表
        self.load_servers()
        
        # 绑定双击事件
        self.server_listbox.bind('<Double-Button-1>', self.apply_server_config)

    def create_widgets(self):
        # 创建服务器列表框
        list_frame = tk.Frame(self.dialog, bg=self.colors['surface'])
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.server_listbox = tk.Listbox(
            list_frame,
            font=self.fonts['body'],
            selectmode=tk.SINGLE,
            relief='solid',
            bd=1
        )
        self.server_listbox.pack(side=tk.LEFT, fill='both', expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.server_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill='y')
        self.server_listbox.config(yscrollcommand=scrollbar.set)
        
        # 创建按钮区域
        button_frame = tk.Frame(self.dialog, bg=self.colors['background'])
        button_frame.pack(fill='x', padx=10, pady=5)
        
        # 添加按钮
        buttons = [
            ("添加服务器", self.add_server, self.colors['primary']),
            ("编辑服务器", self.edit_server, self.colors['primary']),
            ("删除服务器", self.delete_server, self.colors['error']),
            ("测试连接", self.test_connection, self.colors['warning']),
            ("应用选中配置", self.apply_server_config, self.colors['success'])
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                font=self.fonts['button'],
                bg=color,
                fg='white',
                cursor='hand2'
            )
            btn.pack(side=tk.LEFT, padx=5)

    def load_servers(self):
        """加载服务器列表"""
        try:
            # 清空现有列表
            self.server_listbox.delete(0, tk.END)
            
            # 读取配置文件
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                # 添加服务器到列表
                for server in config.get('servers', []):
                    server_name = server.get('name', '')
                    if server_name:
                        self.server_listbox.insert(tk.END, server_name)
                        
        except Exception as e:
            messagebox.showerror("错误", f"加载服务器列表失败: {str(e)}")

    def apply_server_config(self, event=None):
        """应用选中的服务器配置到主界面"""
        selection = self.server_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个服务器配置")
            return
            
        try:
            # 读取配置文件
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 获取选中的服务器配置
            server_name = self.server_listbox.get(selection[0])
            selected_server = None
            
            for server in config.get('servers', []):
                if server.get('name') == server_name:
                    selected_server = server
                    break
            
            if selected_server:
                # 使用 self.app 访问主窗口的配置
                self.app.server_address.set(selected_server.get('address', ''))
                self.app.port.set(selected_server.get('port', '22'))
                self.app.username.set(selected_server.get('username', ''))
                self.app.password.set(self.app.decrypt_password(selected_server['password']))
                self.app.remote_path.set(selected_server.get('remote_path', ''))
                
                messagebox.showinfo("成功", "服务器配置已应用")
                self.dialog.destroy()
            else:
                messagebox.showerror("错误", "未找到选中的服务器配置")
                
        except Exception as e:
            messagebox.showerror("错误", f"应用服务器配置失败: {str(e)}")
            logging.error(f"应用服务器配置失败: {str(e)}", exc_info=True)

    def show(self):
        self.dialog.transient(self.dialog.master)
        self.dialog.grab_set()
        self.dialog.wait_window()

    def add_server(self):
        """添加新服务器配置"""
        try:
            # 创建对话框并等待结果
            dialog = ServerConfigDialog(self.dialog, self.fonts, self.colors)
            result = dialog.show()  # 等待对话框关闭并获取结果
            
            if result:  # 只有当用户点击确定时才继续
                # 读取现有配置
                config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 确保存在 servers 数组
                if 'servers' not in config:
                    config['servers'] = []
                
                # 添加新服务器配置
                server_config = {
                    'name': result['name'],
                    'address': result['address'],
                    'port': result['port'],
                    'username': result['username'],
                    'password': self.app.encrypt_password(result['password']),
                    'remote_path': result['remote_path']
                }
                
                # 检查是否存在同名配置
                for server in config['servers']:
                    if server['name'] == server_config['name']:
                        messagebox.showerror("错误", "已存在同名的服务器配置")
                        return
                
                config['servers'].append(server_config)
                
                # 保存配置
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, ensure_ascii=False, indent=2)
                
                # 刷新列表
                self.load_servers()
                messagebox.showinfo("成功", "服务器配置已添加")
                
        except Exception as e:
            messagebox.showerror("错误", f"添加服务器配置失败: {str(e)}")

    def edit_server(self):
        """编辑选中的服务器配置"""
        selection = self.server_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要编辑的服务器配置")
            return
        
        try:
            # 读取配置文件
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 获取选中的服务器配置
            server_name = self.server_listbox.get(selection[0])
            selected_server = None
            server_index = -1
            
            for i, server in enumerate(config.get('servers', [])):
                if server.get('name') == server_name:
                    selected_server = server
                    server_index = i
                    break
            
            if selected_server:
                # 解密密码
                selected_server['password'] = self.app.decrypt_password(selected_server['password'])
                
                # 打开编辑对话框并等待结果
                dialog = ServerConfigDialog(self.dialog, self.fonts, self.colors, selected_server)
                result = dialog.show()  # 等待对话框关闭并获取结果
                
                if result:  # 只有当用户点击确定时才继续
                    # 更新配置
                    new_config = {
                        'name': result['name'],
                        'address': result['address'],
                        'port': result['port'],
                        'username': result['username'],
                        'password': self.app.encrypt_password(result['password']),
                        'remote_path': result['remote_path']
                    }
                    
                    # 检查是否与其他配置重名
                    for i, server in enumerate(config['servers']):
                        if i != server_index and server['name'] == new_config['name']:
                            messagebox.showerror("错误", "已存在同名的服务器配置")
                            return
                    
                    config['servers'][server_index] = new_config
                    
                    # 保存配置
                    with open(config_file, 'w', encoding='utf-8') as f:
                        json.dump(config, f, ensure_ascii=False, indent=2)
                    
                    # 刷新列表
                    self.load_servers()
                    messagebox.showinfo("成功", "服务器配置已更新")
                    
        except Exception as e:
            messagebox.showerror("错误", f"编辑服务器配置失败: {str(e)}")

    def delete_server(self):
        """删除选中的服务器配置"""
        selection = self.server_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要删除的服务器配置")
            return
        
        if not messagebox.askyesno("确认", "确定要删除选中的服务器配置吗？"):
            return
        
        try:
            # 读取配置文件
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 获取选中的服务器名称
            server_name = self.server_listbox.get(selection[0])
            
            # 删除配置
            config['servers'] = [s for s in config.get('servers', []) if s.get('name') != server_name]
            
            # 保存配置
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            # 刷新列表
            self.load_servers()
            messagebox.showinfo("成功", "服务器配置已删除")
            
        except Exception as e:
            messagebox.showerror("错误", f"删除服务器配置失败: {str(e)}")

    def test_connection(self):
        """测试选中服务器的连接"""
        selection = self.server_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要测试的服务器配置")
            return
        
        try:
            # 读取配置文件
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 获取选中的服务器配置
            server_name = self.server_listbox.get(selection[0])
            selected_server = None
            
            for server in config.get('servers', []):
                if server.get('name') == server_name:
                    selected_server = server
                    break
            
            if selected_server:
                # 创建并显示测试连接对话框
                TestConnectionDialog(
                    self.dialog,
                    selected_server['address'],
                    selected_server['port'],
                    selected_server['username'],
                    self.app.decrypt_password(selected_server['password'])
                )
                
        except Exception as e:
            messagebox.showerror("错误", f"测试连接失败: {str(e)}")


class ServerConfigDialog:
    def __init__(self, parent, fonts, colors, server_config=None):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("服务器配置" if not server_config else "编辑服务器")
        
        # 设置窗口大小和位置
        window_width = 400
        window_height = 350
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.fonts = fonts
        self.colors = colors
        self.dialog.configure(bg=self.colors['background'])
        self.result = None
        
        # 创建输入变量
        self.name = tk.StringVar(value=server_config.get('name', '') if server_config else '')
        self.address = tk.StringVar(value=server_config.get('address', '') if server_config else '')
        self.port = tk.StringVar(value=server_config.get('port', '22') if server_config else '22')
        self.username = tk.StringVar(value=server_config.get('username', '') if server_config else '')
        self.password = tk.StringVar(value=server_config.get('password', '') if server_config else '')
        self.remote_path = tk.StringVar(value=server_config.get('remote_path', '') if server_config else '')
        
        self.create_widgets()
        
    def create_widgets(self):
        # 创建输入框架
        input_frame = tk.Frame(self.dialog, bg=self.colors['surface'])
        input_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # 创建输入字段
        fields = [
            ("服务器名称", self.name),
            ("服务器地址", self.address),
            ("端口号", self.port),
            ("用户名", self.username),
            ("密码", self.password, "*"),
        ]
        
        for i, field in enumerate(fields):
            label = tk.Label(
                input_frame,
                text=field[0],
                font=self.fonts['body'],
                bg=self.colors['surface']
            )
            label.grid(row=i, column=0, sticky='e', padx=5, pady=5)
            
            entry = tk.Entry(
                input_frame,
                textvariable=field[1],
                font=self.fonts['body'],
                show=field[2] if len(field) > 2 else None
            )
            entry.grid(row=i, column=1, sticky='ew', padx=5, pady=5)
        
        # 添加远程路径选择
        remote_path_frame = tk.Frame(input_frame, bg=self.colors['surface'])
        remote_path_frame.grid(row=len(fields), column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        
        tk.Label(
            remote_path_frame,
            text="远程路径",
            font=self.fonts['body'],
            bg=self.colors['surface']
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Entry(
            remote_path_frame,
            textvariable=self.remote_path,
            font=self.fonts['body'],
            width=30
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            remote_path_frame,
            text="选择目录",
            command=self.browse_remote_directory,
            font=self.fonts['button'],
            bg=self.colors['primary'],
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        # 创建按钮区域
        button_frame = tk.Frame(self.dialog, bg=self.colors['background'])
        button_frame.pack(fill='x', padx=20, pady=10)
        
        # 确定按钮
        tk.Button(
            button_frame,
            text="确定",
            command=self.save,
            font=self.fonts['button'],
            bg=self.colors['success'],
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        # 取消按钮
        tk.Button(
            button_frame,
            text="取消",
            command=self.dialog.destroy,
            font=self.fonts['button'],
            bg=self.colors['secondary'],
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
    def save(self):
        """保存配置"""
        # 验证输入
        if not all([
            self.name.get(),
            self.address.get(),
            self.port.get(),
            self.username.get(),
            self.password.get(),
            self.remote_path.get()
        ]):
            messagebox.showerror("错误", "所有字段都必须填写!")
            return
            
        try:
            port = int(self.port.get())
            if port <= 0 or port > 65535:
                messagebox.showerror("错误", "端口号必须在1-65535之间!")
                return
        except ValueError:
            messagebox.showerror("错误", "端口号必须是有效的数字!")
            return
            
        # 保存结果
        self.result = {
            'name': self.name.get(),
            'address': self.address.get(),
            'port': self.port.get(),
            'username': self.username.get(),
            'password': self.password.get(),
            'remote_path': self.remote_path.get()
        }
        
        self.dialog.destroy()

    def show(self):
        """显示对话框并等待用户操作"""
        self.dialog.transient(self.dialog.master)
        self.dialog.grab_set()
        self.dialog.wait_window()
        return self.result

    def browse_remote_directory(self):
        """浏览远程目录"""
        # 验证服务器连接信息
        if not all([self.address.get(), self.username.get(), self.password.get()]):
            messagebox.showerror("错误", "请先填写服务器地址、用户名和密码!")
            return
            
        try:
            # 创建SSH连接
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.address.get(),
                port=int(self.port.get()),
                username=self.username.get(),
                password=self.password.get(),
                timeout=5
            )
            
            # 获取当前选择的远程路径
            current_remote_path = self.remote_path.get()
            
            # 创建目录选择对话框
            dialog = RemoteDirectoryDialog(self.dialog, ssh, current_remote_path)
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


class TestConnectionDialog:
    def __init__(self, parent, host, port, username, password):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("测试连接")
        
        # 设置窗口大小和位置
        window_width = 300
        window_height = 150
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # 保存连接参数
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        
        # 创建界面元素
        self.create_widgets()
        
        # 启动连接测试
        self.testing = True
        self.test_thread = threading.Thread(target=self.test_connection)
        self.test_thread.daemon = True
        self.test_thread.start()
        
        # 启动进度条更新
        self.update_progress()
        
    def create_widgets(self):
        # 创建主框架
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # 状态标签
        self.status_label = tk.Label(
            main_frame,
            text="正在测试连接...",
            font=('Helvetica', 10)
        )
        self.status_label.pack(pady=10)
        
        # 进度条
        self.progress = ttk.Progressbar(
            main_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(pady=10)
        self.progress.start(10)
        
        # 取消按钮
        self.cancel_button = tk.Button(
            main_frame,
            text="取消",
            command=self.cancel_test,
            font=('Helvetica', 10)
        )
        self.cancel_button.pack(pady=10)
    
    def update_progress(self):
        """更新进度条"""
        if self.testing:
            self.dialog.after(100, self.update_progress)
    
    def test_connection(self):
        """测试连接的后台线程"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(
                    self.host,
                    port=int(self.port),
                    username=self.username,
                    password=self.password,
                    timeout=5
                )
                
                ssh.close()
                
                if self.testing:  # 确保没有被取消
                    self.dialog.after(0, self.connection_success)
                    
            except socket.timeout:
                if self.testing:
                    self.dialog.after(0, lambda: self.connection_failed("连接超时，请检查服务器地址是否正确!"))
            except paramiko.ssh_exception.AuthenticationException:
                if self.testing:
                    self.dialog.after(0, lambda: self.connection_failed("认证失败，请检查用户名和密码!"))
            except Exception as error:
                if self.testing:
                    error_msg = str(error)
                    self.dialog.after(0, lambda: self.connection_failed(f"连接失败: {error_msg}"))
                    
        finally:
            # 确保在连接测试结束时停止进度条
            if self.testing:
                self.dialog.after(0, self.stop_progress)
    
    def stop_progress(self):
        """停止进度条动画"""
        self.progress.stop()
        self.progress.pack_forget()  # 隐藏进度条
    
    def connection_success(self):
        """连接成功的处理"""
        self.testing = False
        self.stop_progress()
        self.status_label.config(
            text="连接成功!",
            fg="green"
        )
        self.cancel_button.config(text="关闭")
        messagebox.showinfo("成功", "服务器连接测试成功!")
        self.dialog.destroy()
    
    def connection_failed(self, error_message):
        """连接失败的处理"""
        self.testing = False
        self.stop_progress()
        self.status_label.config(
            text="连接失败!",
            fg="red"
        )
        self.cancel_button.config(text="关闭")
        messagebox.showerror("错误", error_message)
        self.dialog.destroy()
    
    def cancel_test(self):
        """取消测试的处理"""
        self.testing = False
        self.stop_progress()
        self.status_label.config(text="测试已取消")
        self.dialog.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
