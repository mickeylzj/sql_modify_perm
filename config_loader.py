# config_loader.py

import yaml
import os
from typing import Dict, Any, Set

class ConfigLoader:
    """配置文件加载器 - 简化版本"""
    
    def __init__(self, config_path: str = "config.yaml"):
        # 确保配置文件路径是相对于当前工作目录
        if not os.path.isabs(config_path):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_path = os.path.join(current_dir, config_path)
        else:
            self.config_path = config_path
            
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                print(f"配置文件加载成功: {self.config_path}")
                return config
        else:
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项（支持点号分隔的嵌套键）"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def get_db_config(self) -> Dict[str, Any]:
        """获取数据库配置"""
        return self.get('database', {})
    
    def get_system_tables(self) -> Set[str]:
        """获取系统表列表"""
        return set(self.get('system_tables', []))
    
    def get_db_url(self) -> str:
        """构建数据库连接URL"""
        db_config = self.get_db_config()
        
        return (f"mysql+pymysql://{db_config.get('user', 'root')}:"
                f"{db_config.get('password', '')}@"
                f"{db_config.get('host', 'localhost')}:"
                f"{db_config.get('port', 3306)}/"
                f"{db_config.get('database', 'test')}?"
                f"charset={db_config.get('charset', 'utf8mb4')}")
