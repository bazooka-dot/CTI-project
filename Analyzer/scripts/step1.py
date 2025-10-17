from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for our log files"""
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return
        
        # Only watch specific log files
        if event.src_path.endswith(('.log', '.json')):
            print(f"📝 File changed: {event.src_path}")
            print(f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 50)

def main():
    # Path to watch (change this to your log directory)
    path_to_watch = "Honeypots/http/logs"

    print("whatched directory:", path_to_watch)
    print("🔍 Starting Log File Watcher...")
    print(f"📂 Watching directory: {path_to_watch}")
    print("=" * 50)
    
    # Create event handler and observer
    event_handler = LogFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=False)
    
    # Start watching
    observer.start()
    
    try:
        print(" Watcher is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n Stopping watcher...")
        observer.stop()
    
    observer.join()
    print("👋 Watcher stopped.")

if __name__ == "__main__":
    main()