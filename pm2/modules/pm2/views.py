import os
import re
import json
import socket
import subprocess
from datetime import datetime
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.db import connection
from django.contrib.auth import get_user_model
from django.contrib import messages
from users.models import Domain
from users.decorators import loginadminoruser

User = get_user_model()
VHOST_DIR = "/usr/local/lsws/conf/vhosts"

DEFAULT_ROOT_CONTEXT = """context / {
  location                $DOC_ROOT/
  allowBrowse             1

  rewrite  {
    RewriteFile .htaccess
  }
}"""

def get_authenticated_user(request):
    """Retrieves authenticated admin or standard user, respecting admin impersonation"""
    if hasattr(request, 'admin_user') and request.admin_user:
        if request.user and request.user.is_authenticated and request.user != request.admin_user:
            return request.user
        return request.admin_user
    return request.user if request.user.is_authenticated else None

def get_app_user_owner(domain_id):
    """Retrieves the system user owning the domain"""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT u.username 
            FROM domain d
            JOIN auth_user u ON d.userid = u.id
            WHERE d.id = %s
        """, [domain_id])
        row = cursor.fetchone()
        return row[0] if row else 'nobody'

def is_port_free(port):
    """Checks if a port is physically open on localhost"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def find_next_free_port():
    """Finds the next unallocated port starting from 3000"""
    with connection.cursor() as cursor:
        cursor.execute("SELECT port FROM pm2_apps")
        ports_in_db = {row[0] for row in cursor.fetchall()}
        
    port = 3000
    while True:
        if port not in ports_in_db and is_port_free(port):
            return port
        port += 1

def run_pm2_cmd(username, cmd, cwd=None):
    """Runs a PM2 command as the website's specific system user for security isolation"""
    full_cmd = ['sudo', '-H', '-u', username, 'env', 'PATH=/usr/local/bin:/usr/bin:/bin:' + os.environ.get('PATH', ''), 'pm2'] + cmd
    res = subprocess.run(full_cmd, capture_output=True, text=True, cwd=cwd)
    return res

def add_ols_reverse_proxy(domain_name, app_name, port):
    """Appends a reverse proxy extprocessor and context / mapping to OpenLiteSpeed vhost conf"""
    conf_path = os.path.join(VHOST_DIR, domain_name, "vhost.conf")
    if not os.path.exists(conf_path):
        return False
        
    extprocessor_block = f"""extprocessor pm2_proxy_{app_name} {{
  type                    proxy
  address                 http://127.0.0.1:{port}
  maxConns                100
  pcKeepAliveTimeout      60
  initTimeout             60
  retryTimeout            0
  respBuffer              0
}}"""

    context_block = f"""context / {{
  type                    proxy
  handler                 pm2_proxy_{app_name}
  addDefaultCharset       off
}}"""

    with open(conf_path, 'r') as f:
        content = f.read()

    # Clean existing pm2_proxy blocks for this app if they exist
    content = remove_ols_reverse_proxy_from_text(content, app_name)
    # Clean default root context to avoid duplication conflict
    content = remove_generic_root_context(content)

    updated_content = content.rstrip() + "\n\n" + extprocessor_block + "\n\n" + context_block + "\n"

    with open(conf_path, 'w') as f:
        f.write(updated_content)

    # Reload OpenLiteSpeed configuration
    subprocess.run(["/usr/local/lsws/bin/lswsctrl", "reload"])
    return True

def remove_ols_reverse_proxy(domain_name, app_name):
    """Removes the reverse proxy context and restores OLS default root context mapping"""
    conf_path = os.path.join(VHOST_DIR, domain_name, "vhost.conf")
    if not os.path.exists(conf_path):
        return False

    with open(conf_path, 'r') as f:
        content = f.read()

    content = remove_ols_reverse_proxy_from_text(content, app_name)
    
    # If no other context / exists, restore the default static handler
    if "context / {" not in content:
        content = content.rstrip() + "\n\n" + DEFAULT_ROOT_CONTEXT + "\n"

    with open(conf_path, 'w') as f:
        f.write(content)

    # Reload OpenLiteSpeed configuration
    subprocess.run(["/usr/local/lsws/bin/lswsctrl", "reload"])
    return True

def remove_ols_reverse_proxy_from_text(text, app_name):
    pattern_ext = rf"extprocessor\s+pm2_proxy_{app_name}\s*\{{[^}}]*\}}"
    text = re.sub(pattern_ext, "", text, flags=re.DOTALL)
    
    pattern_ctx = rf"context\s+/\s*\{{[^}}]*handler\s+pm2_proxy_{app_name}[^}}]*\}}"
    text = re.sub(pattern_ctx, "", text, flags=re.DOTALL)
    
    return text

def remove_generic_root_context(text):
    pattern = r"context\s+/\s*\{\s*location\s+\$DOC_ROOT/.*?\}"
    text = re.sub(pattern, "", text, flags=re.DOTALL)
    return text


@loginadminoruser
def gui_view(request):
    """Main panel GUI interface"""
    user = get_authenticated_user(request)
    is_impersonating = False
    if hasattr(request, 'admin_user') and request.admin_user:
        if request.user and request.user.is_authenticated and request.user != request.admin_user:
            is_impersonating = True
            
    is_admin = hasattr(request, 'admin_user') and request.admin_user and not is_impersonating
    
    # Fetch domains
    if user.is_superuser or is_admin:
        domains_qs = Domain.objects.all().order_by('domain')
    else:
        domains_qs = Domain.objects.filter(userid=user.id).order_by('domain')
        
    domains = []
    for d in domains_qs:
        username = get_app_user_owner(d.id)
        domains.append({
            'id': d.id,
            'domain': d.domain,
            'username': username,
            'doc_root': f"/home/{username}/{d.domain}"
        })
        
    # Fetch tracked PM2 apps
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("""
                SELECT pa.id, d.domain, pa.name, pa.app_path, pa.script_path, pa.port, pa.env_variables, pa.created_at
                FROM pm2_apps pa
                LEFT JOIN domain d ON pa.domain_id = d.id
            """)
        else:
            cursor.execute("""
                SELECT pa.id, d.domain, pa.name, pa.app_path, pa.script_path, pa.port, pa.env_variables, pa.created_at
                FROM pm2_apps pa
                LEFT JOIN domain d ON pa.domain_id = d.id
                WHERE pa.userid_id = %s
            """, [user.id])
            
        columns = [col[0] for col in cursor.description]
        tracked_apps = [dict(zip(columns, row)) for row in cursor.fetchall()]

    # Fetch live PM2 statuses for each tracked app
    pm2_online = False
    node_version = "Not Detected"
    
    # Check node version
    try:
        node_res = subprocess.run(['node', '-v'], capture_output=True, text=True)
        if node_res.returncode == 0:
            node_version = node_res.stdout.strip()
    except Exception:
        pass
        
    # Determine global system PM2 status
    try:
        pm2_res = subprocess.run(['pm2', '-v'], capture_output=True, text=True)
        pm2_online = (pm2_res.returncode == 0)
    except Exception:
        pass

    # Map real-time process metadata from PM2
    for app in tracked_apps:
        app['status'] = 'offline'
        app['pid'] = '-'
        app['cpu'] = '0'
        app['memory'] = '0'
        app['uptime'] = '-'
        app['restarts'] = '0'
        
        if pm2_online:
            # Query PM2 list for the app owner
            owner = get_app_user_owner(Domain.objects.filter(domain=app['domain']).first().id if app['domain'] else Domain.objects.all().first().id)
            jlist_res = run_pm2_cmd(owner, ['jlist'])
            if jlist_res.returncode == 0:
                try:
                    pm2_list = json.loads(jlist_res.stdout)
                    for pm2_proc in pm2_list:
                        if pm2_proc.get('name') == app['name']:
                            pm_status = pm2_proc.get('pm2_env', {})
                            monit = pm2_proc.get('monit', {})
                            
                            app['status'] = pm_status.get('status', 'offline')
                            app['pid'] = pm2_proc.get('pid', '-')
                            app['cpu'] = f"{monit.get('cpu', 0)}%"
                            
                            # Convert memory bytes to MB
                            mem_bytes = monit.get('memory', 0)
                            app['memory'] = f"{round(mem_bytes / (1024 * 1024), 1)} MB"
                            
                            app['restarts'] = pm_status.get('restart_time', '0')
                            
                            # Calculate uptime
                            uptime_ms = pm_status.get('pm_uptime', 0)
                            if uptime_ms > 0:
                                diff_secs = int((datetime.now().timestamp() * 1000 - uptime_ms) / 1000)
                                if diff_secs < 60:
                                    app['uptime'] = f"{diff_secs}s"
                                elif diff_secs < 3600:
                                    app['uptime'] = f"{diff_secs // 60}m"
                                else:
                                    app['uptime'] = f"{diff_secs // 3600}h"
                except Exception:
                    pass

    base_template = 'whm/base.html' if is_admin else 'users/base.html'

    return render(request, 'pm2/gui.html', {
        'domains': domains,
        'apps': tracked_apps,
        'node_version': node_version,
        'pm2_online': pm2_online,
        'base_template': base_template,
        'user': user,
        'is_admin': is_admin
    })


@loginadminoruser
def install_pm2_view(request):
    """Streams the installation output of Node.js and PM2 in real-time"""
    user = get_authenticated_user(request)
    if not user.is_superuser:
        return HttpResponse("Unauthorized", status=403)

    if request.method != 'POST':
        return HttpResponse("POST required", status=400)

    def stream_output():
        yield "🔽 Initializing Node.js & PM2 system-wide installation...\n"
        
        # Check if node is already installed
        node_installed = False
        try:
            node_res = subprocess.run(['node', '-v'], capture_output=True, text=True)
            node_installed = (node_res.returncode == 0)
        except Exception:
            pass

        if node_installed:
            yield "🟢 Node.js is already installed on the server. Installing PM2 globally via npm...\n"
            cmd = "npm install -g pm2"
        else:
            yield "🟡 Node.js is not detected. Setting up Node.js 20.x and PM2 globally...\n"
            cmd = "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs && npm install -g pm2"

        yield f"🚀 Running command: {cmd}\n\n"
        
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        try:
            for line in iter(process.stdout.readline, ''):
                if line:
                    yield line
            process.wait()
            
            # Dynamically locate and symlink pm2 if not globally available
            if process.returncode == 0:
                if not os.path.exists("/usr/local/bin/pm2"):
                    found_symlink = False
                    for root_dir, dirs, files in os.walk("/usr/local/olspanel/bin/"):
                        if "pm2" in files and root_dir.endswith("/bin"):
                            local_pm2 = os.path.join(root_dir, "pm2")
                            subprocess.run(["ln", "-sf", local_pm2, "/usr/local/bin/pm2"])
                            subprocess.run(["ln", "-sf", os.path.join(root_dir, "pm2-runtime"), "/usr/local/bin/pm2-runtime"])
                            yield f"🔗 Dynamic symlink created for pm2: /usr/local/bin/pm2\n"
                            found_symlink = True
                            break
                    if not found_symlink:
                        # Try standard global path checks
                        for path_dir in ["/usr/local/olspanel/bin/nodejs/24/bin/pm2", "/usr/local/olspanel/bin/nodejs/20/bin/pm2"]:
                            if os.path.exists(path_dir):
                                subprocess.run(["ln", "-sf", path_dir, "/usr/local/bin/pm2"])
                                yield f"🔗 Symlink created: /usr/local/bin/pm2\n"
                                break

                yield "\n✅ PM2 and Node.js are ready and installed successfully!\n"
            else:
                yield f"\n❌ Installation failed with exit code: {process.returncode}\n"
        except Exception as e:
            yield f"\n⚠️ Error during installation: {str(e)}\n"
        finally:
            try:
                process.terminate()
                process.wait()
            except Exception:
                pass
            
        yield "\n🎉 Done! Please reload the page to start deploying apps.\n"

    return StreamingHttpResponse(stream_output(), content_type='text/plain')


@loginadminoruser
def create_app_view(request):
    """API endpoint to create and launch a new Node.js app under PM2"""
    user = get_authenticated_user(request)
    is_admin = hasattr(request, 'admin_user') and request.admin_user
    
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)
        
    domain_id = request.POST.get('domain_id')
    app_name = request.POST.get('name', '').strip().lower()
    app_path = request.POST.get('app_path', '').strip()
    script_path = request.POST.get('script_path', '').strip()
    env_vars_str = request.POST.get('env_variables', '').strip()
    auto_proxy = request.POST.get('auto_proxy') == 'true' or request.POST.get('auto_proxy') == 'on'

    # Validations
    if not app_name or not app_path or not script_path:
        return JsonResponse({"status": "error", "message": "App Name, Directory, and Startup Script are required"}, status=400)

    if not re.match(r'^[a-z0-9_-]+$', app_name):
        return JsonResponse({"status": "error", "message": "App Name must contain only lowercase letters, numbers, hyphens, and underscores"}, status=400)

    # Validate domain ownership
    domain = None
    if domain_id:
        if user.is_superuser or is_admin:
            domain = get_object_or_404(Domain, id=domain_id)
        else:
            domain = get_object_or_404(Domain, id=domain_id, userid=user.id)

    # Verify app name uniqueness
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM pm2_apps WHERE name = %s", [app_name])
        if cursor.fetchone():
            return JsonResponse({"status": "error", "message": "An app with this name is already registered"}, status=400)

    # Find a free port for this app
    port = find_next_free_port()

    # Determine site user owner
    username = get_app_user_owner(domain.id) if domain else 'nobody'

    # Ensure app directory exists and belongs to the site user
    if not os.path.exists(app_path):
        return JsonResponse({"status": "error", "message": f"App Directory does not exist on disk: {app_path}"}, status=400)

    # Parse and write environment variables to local .env file in the app directory
    env_vars = {}
    if env_vars_str:
        for line in env_vars_str.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k.strip()] = v.strip()

    # Always inject target PORT
    env_vars['PORT'] = str(port)

    # Write .env file
    env_file_path = os.path.join(app_path, '.env')
    try:
        with open(env_file_path, 'w', encoding='utf-8') as f:
            for k, v in env_vars.items():
                f.write(f"{k}={v}\n")
        # Set ownership of .env file
        subprocess.run(['chown', f"{username}:{username}", env_file_path])
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Failed to write .env file: {str(e)}"}, status=500)

    # Start the app under PM2 as the specific site user
    # Check if starting via script path directly or as an npm start command
    if script_path.startswith('npm '):
        # e.g. npm run start
        npm_args = script_path.split(' ')[1:]
        pm2_cmd = ['start', 'npm', '--name', app_name, '--'] + npm_args
    else:
        pm2_cmd = ['start', script_path, '--name', app_name]

    # Run the start command
    res = run_pm2_cmd(username, pm2_cmd, cwd=app_path)
    if res.returncode != 0:
        return JsonResponse({"status": "error", "message": f"PM2 launch error: {res.stderr or res.stdout}"}, status=500)

    # Save to Database
    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO pm2_apps (userid_id, domain_id, name, app_path, script_path, port, env_variables, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, [user.id, domain.id if domain else None, app_name, app_path, script_path, port, env_vars_str, datetime.now()])

    # Auto-configure OpenLiteSpeed Proxy Context
    if auto_proxy and domain:
        add_ols_reverse_proxy(domain.domain, app_name, port)

    return JsonResponse({"status": "success", "message": f"App '{app_name}' registered and launched successfully on port {port}"})


@loginadminoruser
def action_view(request, app_id):
    """API endpoint to trigger PM2 start/stop/restart/delete actions"""
    user = get_authenticated_user(request)
    is_admin = hasattr(request, 'admin_user') and request.admin_user
    action = request.GET.get('action')

    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)

    # Fetch app
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id, name, domain_id, app_path, port FROM pm2_apps WHERE id = %s", [app_id])
        else:
            cursor.execute("SELECT id, name, domain_id, app_path, port FROM pm2_apps WHERE id = %s AND userid_id = %s", [app_id, user.id])
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"status": "error", "message": "Application not found"}, status=404)

    app_id_db, app_name, domain_id, app_path, port = row
    username = get_app_user_owner(domain_id) if domain_id else 'nobody'

    if action == 'stop':
        res = run_pm2_cmd(username, ['stop', app_name])
    elif action == 'start':
        res = run_pm2_cmd(username, ['start', app_name])
    elif action == 'restart':
        res = run_pm2_cmd(username, ['restart', app_name])
    elif action == 'delete':
        # Remove proxy context from OLS if configured
        domain = Domain.objects.filter(id=domain_id).first() if domain_id else None
        if domain:
            remove_ols_reverse_proxy(domain.domain, app_name)
            
        # Delete from PM2
        res = run_pm2_cmd(username, ['delete', app_name])
        
        # Delete from Database
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM pm2_apps WHERE id = %s", [app_id])
            
        return JsonResponse({"status": "success", "message": f"Application '{app_name}' deleted successfully"})
    else:
        return JsonResponse({"status": "error", "message": "Invalid action"}, status=400)

    if res.returncode != 0:
        return JsonResponse({"status": "error", "message": f"PM2 Action Error: {res.stderr or res.stdout}"}, status=500)

    return JsonResponse({"status": "success", "message": f"Application '{app_name}' action completed successfully"})


@loginadminoruser
def save_env_view(request, app_id):
    """API endpoint to update .env configurations for an application"""
    user = get_authenticated_user(request)
    is_admin = hasattr(request, 'admin_user') and request.admin_user
    
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)

    env_vars_str = request.POST.get('env_variables', '').strip()

    # Fetch app
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id, name, domain_id, app_path, port FROM pm2_apps WHERE id = %s", [app_id])
        else:
            cursor.execute("SELECT id, name, domain_id, app_path, port FROM pm2_apps WHERE id = %s AND userid_id = %s", [app_id, user.id])
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"status": "error", "message": "Application not found"}, status=404)

    app_id_db, app_name, domain_id, app_path, port = row
    username = get_app_user_owner(domain_id) if domain_id else 'nobody'

    # Rebuild env variables
    env_vars = {}
    if env_vars_str:
        for line in env_vars_str.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k.strip()] = v.strip()

    # Inject port
    env_vars['PORT'] = str(port)

    # Rewrite .env
    env_file_path = os.path.join(app_path, '.env')
    try:
        with open(env_file_path, 'w', encoding='utf-8') as f:
            for k, v in env_vars.items():
                f.write(f"{k}={v}\n")
        subprocess.run(['chown', f"{username}:{username}", env_file_path])
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Failed to update .env: {str(e)}"}, status=500)

    # Save to Database
    with connection.cursor() as cursor:
        cursor.execute("UPDATE pm2_apps SET env_variables = %s WHERE id = %s", [env_vars_str, app_id])

    # Restart app to apply env modifications
    run_pm2_cmd(username, ['restart', app_name])

    return JsonResponse({"status": "success", "message": "Environment variables updated and app restarted successfully"})


@loginadminoruser
def logs_view(request, app_name):
    """Streams the log output of a given PM2 app in real-time"""
    user = get_authenticated_user(request)
    is_admin = hasattr(request, 'admin_user') and request.admin_user

    # Verify ownership of the app
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT domain_id FROM pm2_apps WHERE name = %s", [app_name])
        else:
            cursor.execute("SELECT domain_id FROM pm2_apps WHERE name = %s AND userid_id = %s", [app_name, user.id])
        row = cursor.fetchone()

    if not row:
        return HttpResponse("Unauthorized", status=403)

    domain_id = row[0]
    username = get_app_user_owner(domain_id) if domain_id else 'nobody'

    def log_stream():
        # Open pm2 logs command as a process and stream stdout
        full_cmd = ['sudo', '-H', '-u', username, 'pm2', 'logs', app_name, '--raw', '--lines', '100']
        process = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        try:
            for line in iter(process.stdout.readline, ''):
                if line:
                    yield line
        except Exception:
            pass
        finally:
            process.terminate()
            process.wait()

    return StreamingHttpResponse(log_stream(), content_type='text/plain')


@loginadminoruser
def add_app_view(request):
    """Page to add and launch a new Node.js application under PM2"""
    user = get_authenticated_user(request)
    is_impersonating = False
    if hasattr(request, 'admin_user') and request.admin_user:
        if request.user and request.user.is_authenticated and request.user != request.admin_user:
            is_impersonating = True
            
    is_admin = hasattr(request, 'admin_user') and request.admin_user and not is_impersonating
    
    # Fetch domains
    if user.is_superuser or is_admin:
        domains_qs = Domain.objects.all().order_by('domain')
    else:
        domains_qs = Domain.objects.filter(userid=user.id).order_by('domain')
        
    domains = []
    for d in domains_qs:
        username = get_app_user_owner(d.id)
        domains.append({
            'id': d.id,
            'domain': d.domain,
            'username': username,
            'doc_root': f"/home/{username}/{d.domain}"
        })

    if request.method == 'POST':
        domain_id = request.POST.get('domain_id')
        app_name = request.POST.get('name', '').strip().lower()
        app_path = request.POST.get('app_path', '').strip()
        script_path = request.POST.get('script_path', '').strip()
        env_vars_str = request.POST.get('env_variables', '').strip()
        auto_proxy = request.POST.get('auto_proxy') == 'true' or request.POST.get('auto_proxy') == 'on'

        # Validations
        if not app_name or not app_path or not script_path:
            messages.error(request, "App Name, Directory, and Startup Script are required")
            return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        if not re.match(r'^[a-z0-9_-]+$', app_name):
            messages.error(request, "App Name must contain only lowercase letters, numbers, hyphens, and underscores")
            return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        # Validate domain ownership
        domain = None
        if domain_id:
            if user.is_superuser or is_admin:
                domain = get_object_or_404(Domain, id=domain_id)
            else:
                domain = get_object_or_404(Domain, id=domain_id, userid=user.id)

        # Verify app name uniqueness
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM pm2_apps WHERE name = %s", [app_name])
            if cursor.fetchone():
                messages.error(request, "An app with this name is already registered")
                return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        # Find a free port for this app
        port = find_next_free_port()

        # Determine site user owner
        username = get_app_user_owner(domain.id) if domain else 'nobody'

        # Ensure app directory exists and belongs to the site user
        if not os.path.exists(app_path):
            messages.error(request, f"App Directory does not exist on disk: {app_path}")
            return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        # Parse and write environment variables to local .env file in the app directory
        env_vars = {}
        if env_vars_str:
            for line in env_vars_str.split('\n'):
                if '=' in line:
                    k, v = line.split('=', 1)
                    env_vars[k.strip()] = v.strip()

        # Always inject target PORT
        env_vars['PORT'] = str(port)

        # Write .env file
        env_file_path = os.path.join(app_path, '.env')
        try:
            with open(env_file_path, 'w', encoding='utf-8') as f:
                for k, v in env_vars.items():
                    f.write(f"{k}={v}\n")
            # Set ownership of .env file
            subprocess.run(['chown', f"{username}:{username}", env_file_path])
        except Exception as e:
            messages.error(request, f"Failed to write .env file: {str(e)}")
            return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        # Start the app under PM2 as the specific site user
        if script_path.startswith('npm '):
            npm_args = script_path.split(' ')[1:]
            pm2_cmd = ['start', 'npm', '--name', app_name, '--'] + npm_args
        else:
            pm2_cmd = ['start', script_path, '--name', app_name]

        # Run the start command
        res = run_pm2_cmd(username, pm2_cmd, cwd=app_path)
        if res.returncode != 0:
            messages.error(request, f"PM2 launch error: {res.stderr or res.stdout}")
            return render(request, 'pm2/add.html', {'domains': domains, 'form_data': request.POST})

        # Save to Database
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO pm2_apps (userid_id, domain_id, name, app_path, script_path, port, env_variables, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, [user.id, domain.id if domain else None, app_name, app_path, script_path, port, env_vars_str, datetime.now()])

        # Auto-configure OpenLiteSpeed Proxy Context
        if auto_proxy and domain:
            add_ols_reverse_proxy(domain.domain, app_name, port)

        messages.success(request, f"App '{app_name}' registered and launched successfully on port {port}!")
        return redirect('pm2_gui')

    return render(request, 'pm2/add.html', {'domains': domains})
