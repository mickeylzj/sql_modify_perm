import yaml
import os
from typing import Dict, Any

class ConfigLoader:
    """配置文件加载器"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as file:
                    config = yaml.safe_load(file)
                    print(f"配置文件加载成功: {self.config_path}")
                    return config
            else:
                print(f"配置文件不存在，使用默认配置: {self.config_path}")
                return self._get_default_config()
        except Exception as e:
            print(f"配置文件加载失败: {e}，使用默认配置")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            'database': {
                'host': 'localhost',
                'port': 3306,
                'user': 'root',
                'password': '123456',
                'database': 'data_permission_system',
                'charset': 'utf8mb4'
            },
            'system_tables': ['employee', 'salary', 'age', 'company'],
            'cache': {'default_ttl': 300},
            'environment': {'debug': True, 'log_level': 'INFO'}
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项（支持嵌套键）"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_db_config(self) -> Dict[str, Any]:
        """获取数据库配置"""
        return self.config.get('database', {})
    
    def get_system_tables(self) -> set:
        """获取系统表列表"""
        return set(self.config.get('system_tables', []))
