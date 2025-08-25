# TODO: 写个说明文档，创建的表结构（把表定义成ORM结构，数据库没有表自动创建）
# TODO:ORM

from collections import deque
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker
from database_models import Base, PermissionRule, UserRole, UserRoleMapping, PermissionLog
from typing import Dict, List, Optional, Tuple, Set
import json
import time
import re
from loguru import logger

from config_loader import ConfigLoader
from sql_parser import SQLTableExtractor

class UserManager:
    """用户信息管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def get_user_basic_info(self, user_id: int) -> Dict:
        """获取用户基本信息"""
        session = self.SessionLocal()
        try:
            user_result = session.execute(
                text("SELECT user_id, user_name, company_id, role FROM employee WHERE user_id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if not user_result:
                raise ValueError(f"用户 {user_id} 不存在")
            
            return {
                'user_id': user_result[0],
                'user_name': user_result[1],
                'company_id': user_result[2],
                'role': user_result[3]
            }
        finally:
            session.close()
    
    def get_effective_role(self, user_id: int, default_role: str) -> str:
        """获取用户有效角色"""
        session = self.SessionLocal()
        try:
            role_mapping = session.query(UserRoleMapping).join(UserRole).filter(
                UserRoleMapping.user_id == user_id,
                UserRoleMapping.is_active == True,
                UserRole.is_active == True
            ).first()
            
            return role_mapping.role.role_name if role_mapping else default_role
        finally:
            session.close()

class PermissionManager:
    """权限管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def get_permission_rules(self) -> List[PermissionRule]:
        """获取活动的权限规则"""
        session = self.SessionLocal()
        try:
            return session.query(PermissionRule).filter(
                PermissionRule.is_active == True
            ).order_by(PermissionRule.priority.desc()).all()
        finally:
            session.close()
    
    def build_user_permissions(self, rules: List[PermissionRule], user_info: Dict, 
                             user_role: str, system_tables: Set[str]) -> Dict:
        """构建用户权限"""
        permissions = {}
        
        for rule in rules:
            try:
                target_roles = json.loads(rule.target_roles) if rule.target_roles else []
                if user_role not in target_roles and '*' not in target_roles:
                    continue
                
                tables_to_apply = system_tables if rule.table_name == '*' else [rule.table_name]
                
                for table_name in tables_to_apply:
                    if table_name not in permissions:
                        permissions[table_name] = {'access': True, 'row_filter': None}
                    
                    if rule.filter_type.value == 'deny_all':
                        permissions[table_name]['access'] = False
                    elif rule.filter_type.value == 'custom_sql' and rule.filter_sql:
                        permissions[table_name]['row_filter'] = rule.filter_sql
                    elif rule.filter_type.value == 'allow_all':
                        permissions[table_name]['row_filter'] = None
                        
            except json.JSONDecodeError:
                logger.warning(f"无效的角色配置: {rule.target_roles}")
                continue
        
        return permissions

# 服务器缓存存在多个进程，每个进程有不同cache，每个redis有不同cache，每个cache有不同ttl
# 没有cache也可以
class CacheManager:
    """缓存管理类"""
    
    def __init__(self, cache_ttl: int = 300):
        self.cache_ttl = cache_ttl
        self.permission_cache = {}
        self.rule_cache = {}
        self.user_info_cache = {}
        
        logger.info("数据缓存管理器初始化完成")
    
    def get(self, cache_key: str, cache_type: str = 'permission') -> Optional[any]:
        """获取缓存数据"""
        cache_dict = self._get_cache_dict(cache_type)
        if cache_key in cache_dict:
            cached_data, timestamp = cache_dict[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                logger.info(f"使用缓存数据: {cache_type}:{cache_key}")
                return cached_data
            else:
                del cache_dict[cache_key]
                logger.info(f"缓存已过期，删除: {cache_type}:{cache_key}")
        return None
    
    def set(self, cache_key: str, data: any, cache_type: str = 'permission'):
        """设置缓存数据"""
        cache_dict = self._get_cache_dict(cache_type)
        cache_dict[cache_key] = (data, time.time())
        logger.info(f"数据已缓存: {cache_type}:{cache_key}")
    
    def clear(self, cache_type: Optional[str] = None):
        """清除缓存"""
        if cache_type is None:
            self.permission_cache.clear()
            self.rule_cache.clear()
            self.user_info_cache.clear()
            logger.info("所有缓存已清除")
        else:
            cache_dict = self._get_cache_dict(cache_type)
            cache_dict.clear()
            logger.info(f"{cache_type}缓存已清除")
    
    def _get_cache_dict(self, cache_type: str) -> Dict:
        """获取对应类型的缓存字典"""
        if cache_type == 'permission':
            return self.permission_cache
        elif cache_type == 'rule':
            return self.rule_cache
        elif cache_type == 'user_info':
            return self.user_info_cache
        else:
            raise ValueError(f"未知的缓存类型: {cache_type}")

# TODO：try直接删了
class RefactoredPermissionController:
    """重构后的权限控制器"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """初始化权限控制器"""
        # 加载配置
        self.config = ConfigLoader(config_path)
        
        # 初始化数据库
        self._init_database()
        
        # 初始化组件
        self.user_manager = UserManager(self.SessionLocal)
        self.permission_manager = PermissionManager(self.SessionLocal)
        self.cache_manager = CacheManager(self.config.get('cache.default_ttl', 300))
        
        # 初始化SQL解析器
        self.system_tables = self.config.get_system_tables()
        self.sql_extractor = SQLTableExtractor(self.system_tables)
        
        logger.info("重构版权限控制器初始化完成")
        self._ensure_database_ready()
    
    def _init_database(self):
        """初始化数据库连接"""
        db_config = self.config.get_db_config()
        
        self.db_url = (f"mysql+pymysql://{db_config['user']}:{db_config['password']}@"
                      f"{db_config['host']}:{db_config.get('port', 3306)}/"
                      f"{db_config['database']}?charset={db_config.get('charset', 'utf8mb4')}")
        
        self.engine = create_engine(
            self.db_url,
            echo=self.config.get('environment.debug', False),
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=10,
            max_overflow=20
        )
        
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def _ensure_database_ready(self):
        """确保数据库表结构就绪"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("数据库表结构检查完成")
        except Exception as e:
            logger.error(f"数据库表结构检查失败: {e}")
    
    def get_user_permissions_with_cache(self, user_id: int) -> Dict:
        """获取用户权限（带缓存）"""
        cache_key = f"user_perm_{user_id}"
        cached_data = self.cache_manager.get(cache_key, 'permission')
        
        if cached_data:
            return cached_data
        
        try:
            # 获取用户信息
            user_info = self.user_manager.get_user_basic_info(user_id)
            
            # 获取有效角色
            effective_role = self.user_manager.get_effective_role(user_id, user_info['role'])
            
            # 获取权限规则
            rules = self.get_permission_rules_with_cache()
            
            # 构建权限
            permissions = self.permission_manager.build_user_permissions(
                rules, user_info, effective_role, self.system_tables
            )
            
            # 构建结果
            result = {
                **user_info,
                'effective_role': effective_role,
                'table_permissions': permissions
            }
            
            # 缓存结果
            self.cache_manager.set(cache_key, result, 'permission')
            
            return result
            
        except Exception as e:
            logger.error(f"获取用户权限失败: {e}")
            raise
    
    def get_permission_rules_with_cache(self) -> List:
        """获取权限规则（带缓存）"""
        cache_key = "permission_rules"
        cached_rules = self.cache_manager.get(cache_key, 'rule')
        
        if cached_rules:
            return cached_rules
        
        rules = self.permission_manager.get_permission_rules()
        self.cache_manager.set(cache_key, rules, 'rule')
        
        return rules
    
    def extract_table_info_with_schema(self, sql: str) -> Dict[str, str]:
        """提取表信息，支持schema.table格式"""
        return self.sql_extractor.extract_table_info_with_schema(sql)
    
    def execute_query_with_permissions(self, sql: str, user_id: int) -> Dict:
        start_time = time.time()
        execution_info = {
            'user_id': user_id,
            'original_sql': sql,
            'table_names': [],
            'result': None,
            'status': 'unknown',
            'execution_time': 0,
            'error_message': None
        }
        
        try:
            logger.info(f"开始执行权限控制查询 - 用户: {user_id}")
            
            # 提取表信息
            table_info = self.extract_table_info_with_schema(sql)
            execution_info['table_names'] = list(table_info.keys())
            
            logger.info(f"检测到的表: {execution_info['table_names']}")
            logger.info(f"表别名映射: {table_info}")

            # TODO: 系统表存在数据库，不用本地在配置（存配置文件/存数据库）
            if not table_info:
                # 如果没有系统表，直接执行
                session = self.SessionLocal()
                try:
                    result = session.execute(text(sql)).fetchall()
                    execution_info['result'] = [tuple(row) for row in result]
                    execution_info['status'] = 'success'
                finally:
                    session.close()
            else:
                # 如果有系统表，检查权限（暂时简化，直接执行）
                session = self.SessionLocal()
                try:
                    result = session.execute(text(sql)).fetchall()
                    execution_info['result'] = [tuple(row) for row in result]
                    execution_info['status'] = 'success'
                    logger.info(f"查询执行成功，返回 {len(execution_info['result'])} 条记录")
                finally:
                    session.close()
            
        except Exception as e:
            execution_info['status'] = 'error'
            execution_info['error_message'] = str(e)
            logger.error(f"查询执行失败: {e}")
        
        finally:
            execution_info['execution_time'] = int((time.time() - start_time) * 1000)
        
        return execution_info