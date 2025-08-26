# integrated_permission_controller.py

from collections import deque
from sqlalchemy import text, create_engine, and_
from sqlalchemy.orm import sessionmaker
from database_models import (Base, PermissionRule, UserRole, UserRoleMapping, PermissionLog, 
                            Employee, Company, Salary, Age, PermissionType, FilterType)
from typing import Dict, List, Optional, Tuple, Set
import json
import time
import re
from datetime import datetime
from loguru import logger

from config_loader import ConfigLoader
from sql_parser import SQLTableExtractor

class UserManager:
    """用户信息管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    # TODO： 函数应当返回ORM，用到这个函数返回值的地方也要用ORM，才是ORM结构化的优势和意义
    def get_user_basic_info(self, user_id: int) -> Dict:
        """获取用户基本信息"""
        session = self.SessionLocal()
        try:
            # ✅ 使用ORM查询而不是原始SQL
            employee = session.query(Employee).filter(
                Employee.user_id == user_id
            ).first()
            
            if not employee:
                raise ValueError(f"用户 {user_id} 不存在")
            
            return {
                'user_id': employee.user_id,
                'user_name': employee.user_name,
                'company_id': employee.company_id,
                'role': employee.role
            }
        finally:
            session.close()
    
    # TODO： effective_role如无必要 可删除
    def get_effective_role(self, user_id: int, default_role: str) -> str:
        """获取用户有效角色"""
        session = self.SessionLocal()
        try:
            role_mapping = session.query(UserRoleMapping).join(UserRole).filter(
                and_(
                    UserRoleMapping.user_id == user_id,
                    UserRoleMapping.is_active == True,
                    UserRole.is_active == True
                )
            ).first()
            
            return role_mapping.role.role_name if role_mapping else default_role
        finally:
            session.close()
    
    def create_user(self, user_name: str, company_id: int, role: str) -> Employee:
        """创建新用户"""
        session = self.SessionLocal()
        try:
            new_employee = Employee(
                user_name=user_name,
                company_id=company_id,
                role=role
            )
            session.add(new_employee)
            session.commit()
            session.refresh(new_employee)
            logger.info(f"创建新用户: {user_name}, ID: {new_employee.user_id}")
            return new_employee
        except Exception as e:
            session.rollback()
            logger.error(f"创建用户失败: {e}")
            raise e
        finally:
            session.close()
    
    def update_user_role(self, user_id: int, new_role: str) -> bool:
        """更新用户角色"""
        session = self.SessionLocal()
        try:
            employee = session.query(Employee).filter(
                Employee.user_id == user_id
            ).first()
            
            if employee:
                old_role = employee.role
                employee.role = new_role
                session.commit()
                logger.info(f"用户 {user_id} 角色更新: {old_role} -> {new_role}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"更新用户角色失败: {e}")
            raise e
        finally:
            session.close()
    
    def get_users_by_company(self, company_id: int) -> List[Employee]:
        """获取公司所有用户"""
        session = self.SessionLocal()
        try:
            employees = session.query(Employee).filter(
                Employee.company_id == company_id
            ).all()
            return employees
        finally:
            session.close()

class PermissionManager:
    """权限管理类 - 完全ORM版本"""
    
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
    
    def create_permission_rule(self, rule_name: str, table_name: str, 
                              permission_type: PermissionType, filter_type: FilterType,
                              target_roles: List[str], **kwargs) -> PermissionRule:
        """创建权限规则"""
        session = self.SessionLocal()
        try:
            rule = PermissionRule(
                rule_name=rule_name,
                table_name=table_name,
                permission_type=permission_type,
                filter_type=filter_type,
                target_roles=json.dumps(target_roles),
                created_at=datetime.now(),
                updated_at=datetime.now(),
                **kwargs
            )
            session.add(rule)
            session.commit()
            session.refresh(rule)
            logger.info(f"创建权限规则: {rule_name}, ID: {rule.rule_id}")
            return rule
        except Exception as e:
            session.rollback()
            logger.error(f"创建权限规则失败: {e}")
            raise e
        finally:
            session.close()
    
    def update_permission_rule(self, rule_id: int, **updates) -> bool:
        """更新权限规则"""
        session = self.SessionLocal()
        try:
            rule = session.query(PermissionRule).filter(
                PermissionRule.rule_id == rule_id
            ).first()
            
            if rule:
                for key, value in updates.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                rule.updated_at = datetime.now()
                session.commit()
                logger.info(f"更新权限规则 {rule_id}: {updates}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"更新权限规则失败: {e}")
            raise e
        finally:
            session.close()
    
    def get_rules_by_table(self, table_name: str) -> List[PermissionRule]:
        """获取特定表的权限规则"""
        session = self.SessionLocal()
        try:
            return session.query(PermissionRule).filter(
                and_(
                    PermissionRule.table_name.in_([table_name, '*']),
                    PermissionRule.is_active == True
                )
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
                    
                    if rule.filter_type == FilterType.DENY_ALL:
                        permissions[table_name]['access'] = False
                    elif rule.filter_type == FilterType.CUSTOM_SQL and rule.filter_sql:
                        permissions[table_name]['row_filter'] = rule.filter_sql
                    elif rule.filter_type == FilterType.ALLOW_ALL:
                        permissions[table_name]['row_filter'] = None
                        
            except json.JSONDecodeError:
                logger.warning(f"无效的角色配置: {rule.target_roles}")
                continue
        
        return permissions

class LogManager:
    """日志管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def log_query_execution(self, user_id: int, original_sql: str, modified_sql: str = None,
                          table_names: List[str] = None, status: str = 'unknown',
                          execution_time: int = 0, error_message: str = None) -> PermissionLog:
        """记录查询执行日志"""
        session = self.SessionLocal()
        try:
            log_entry = PermissionLog(
                user_id=user_id,
                original_sql=original_sql,
                modified_sql=modified_sql,
                table_names=json.dumps(table_names or []),
                execution_result=status,
                execution_time=execution_time,
                error_message=error_message,
                created_at=datetime.now()
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            return log_entry
        except Exception as e:
            session.rollback()
            logger.error(f"记录日志失败: {e}")
            raise e
        finally:
            session.close()
    
    def get_user_logs(self, user_id: int, limit: int = 100) -> List[PermissionLog]:
        """获取用户操作日志"""
        session = self.SessionLocal()
        try:
            return session.query(PermissionLog).filter(
                PermissionLog.user_id == user_id
            ).order_by(PermissionLog.created_at.desc()).limit(limit).all()
        finally:
            session.close()
    
    def get_failed_queries(self, hours: int = 24) -> List[PermissionLog]:
        """获取失败的查询"""
        session = self.SessionLocal()
        try:
            from datetime import datetime, timedelta
            since = datetime.now() - timedelta(hours=hours)
            
            return session.query(PermissionLog).filter(
                and_(
                    PermissionLog.execution_result.in_(['error', 'permission_denied']),
                    PermissionLog.created_at >= since
                )
            ).order_by(PermissionLog.created_at.desc()).all()
        finally:
            session.close()

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

class RefactoredPermissionController:
    """重构后的权限控制器 - 完全ORM版本"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """初始化权限控制器"""
        # 加载配置
        self.config = ConfigLoader(config_path)
        
        # 初始化数据库
        self._init_database()
        
        # 初始化组件
        self.user_manager = UserManager(self.SessionLocal)
        self.permission_manager = PermissionManager(self.SessionLocal)
        self.log_manager = LogManager(self.SessionLocal)
        self.cache_manager = CacheManager(self.config.get('cache.default_ttl', 300))
        
        # 初始化SQL解析器
        # TODO: system_tables应该从数据库获取，作为需要权限管控的表？
        self.system_tables = self.config.get_system_tables()
        self.sql_extractor = SQLTableExtractor(self.system_tables)
        
        logger.info("重构版权限控制器初始化完成")
        self._ensure_database_ready()
    
    def _init_database(self):
        """初始化数据库连接"""
        db_config = self.config.get_db_config()
        
        # 这个db_url可以在 config.py中封装一个函数
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
        """确保数据库表结构就绪 - ORM自动建表"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("✅ ORM自动建表完成 - 数据库表结构检查完成")
        except Exception as e:
            logger.error(f"❌ ORM自动建表失败: {e}")
    

    # TODO: 以下函数内effective_role , 无用可全部删去
    def get_user_permissions_with_cache(self, user_id: int) -> Dict:
        """获取用户权限（带缓存）- ORM版本"""
        cache_key = f"user_perm_{user_id}"
        cached_data = self.cache_manager.get(cache_key, 'permission')
        
        if cached_data:
            return cached_data
        
        # 获取用户信息 - 使用ORM
        user_info = self.user_manager.get_user_basic_info(user_id)
        
        # 获取有效角色 - 使用ORM
        effective_role = self.user_manager.get_effective_role(user_id, user_info['role'])
        
        # 获取权限规则 - 使用ORM
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
    
    def get_permission_rules_with_cache(self) -> List:
        """获取权限规则（带缓存）- ORM版本"""
        cache_key = "permission_rules"
        cached_rules = self.cache_manager.get(cache_key, 'rule')
        
        if cached_rules:
            return cached_rules
        
        # 使用ORM获取规则
        # TODO: 从数据库读取信息的时候，建议加一个logger日志，方便排查问题，比如什么时候开始读取、什么时候读取完成，比如读取了多少条等等
        rules = self.permission_manager.get_permission_rules()
        self.cache_manager.set(cache_key, rules, 'rule')
        
        return rules
    
    # TODO: 这个函数是否有必要？
    def extract_table_info_with_schema(self, sql: str) -> Dict[str, str]:
        """提取表信息，支持schema.table格式"""
        return self.sql_extractor.extract_table_info_with_schema(sql)
    
    def execute_query_with_permissions(self, sql: str, user_id: int, log_execution: bool = True) -> Dict:
        """执行带权限控制的查询"""
        start_time = time.time()

        # TODO： 可以直接使用 PermissionLog ORM，有ORM就不要用dict
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
            logger.info(f"🚀 开始执行权限控制查询 - 用户: {user_id}")
            
            # 提取表信息
            table_info = self.extract_table_info_with_schema(sql)
            execution_info['table_names'] = list(table_info.keys())
            
            logger.info(f"📋 检测到的表: {execution_info['table_names']}")
            logger.info(f"🏷️ 表别名映射: {table_info}")
            
            if not table_info:
                # 如果没有系统表，直接执行
                result = self._execute_sql_direct(sql)
                execution_info['result'] = result
                execution_info['status'] = 'success'
            else:
                # 如果有系统表，应用权限控制
                # TODO: 实现真正的权限控制和SQL改写
                # 目前暂时简化处理
                result = self._execute_sql_direct(sql)
                execution_info['result'] = result
                execution_info['status'] = 'success'
                logger.info(f"✅ 查询执行成功，返回 {len(execution_info['result'])} 条记录")
            
        except Exception as e:
            execution_info['status'] = 'error'
            execution_info['error_message'] = str(e)
            logger.error(f"❌ 查询执行失败: {e}")
        
        finally:
            execution_info['execution_time'] = int((time.time() - start_time) * 1000)
        
        # 使用ORM记录日志
        if log_execution:
            try:
                self.log_manager.log_query_execution(
                    user_id=execution_info['user_id'],
                    original_sql=execution_info['original_sql'],
                    table_names=execution_info['table_names'],
                    status=execution_info['status'],
                    execution_time=execution_info['execution_time'],
                    error_message=execution_info['error_message']
                )
            except Exception as log_error:
                logger.error(f"记录日志失败: {log_error}")
        
        return execution_info
    
    def _execute_sql_direct(self, sql: str) -> List[Tuple]:
        """直接执行SQL - 仍然需要原始SQL执行"""
        session = self.SessionLocal()
        try:
            result = session.execute(text(sql)).fetchall()
            return [tuple(row) for row in result]
        finally:
            session.close()
    
    # === 新增的ORM便捷方法 ===

    # TODO: 以下函数是否有用？
    
    def create_user(self, user_name: str, company_id: int, role: str) -> Employee:
        """创建用户"""
        return self.user_manager.create_user(user_name, company_id, role)
    
    def create_permission_rule(self, rule_name: str, table_name: str, 
                              permission_type: str, filter_type: str,
                              target_roles: List[str], **kwargs) -> PermissionRule:
        """创建权限规则"""
        perm_type = PermissionType(permission_type)
        filt_type = FilterType(filter_type)
        return self.permission_manager.create_permission_rule(
            rule_name, table_name, perm_type, filt_type, target_roles, **kwargs
        )
    
    def get_user_query_history(self, user_id: int, limit: int = 50) -> List[PermissionLog]:
        """获取用户查询历史"""
        return self.log_manager.get_user_logs(user_id, limit)
    
    def get_company_users(self, company_id: int) -> List[Employee]:
        """获取公司用户列表"""
        return self.user_manager.get_users_by_company(company_id)
    
    def update_user_role(self, user_id: int, new_role: str) -> bool:
        """更新用户角色"""
        return self.user_manager.update_user_role(user_id, new_role)
    
    def get_failed_queries_report(self, hours: int = 24) -> List[PermissionLog]:
        """获取失败查询报告"""
        return self.log_manager.get_failed_queries(hours)
    
    def clear_all_cache(self):
        """清除所有缓存"""
        self.cache_manager.clear()
        logger.info("🧹 所有缓存已清除")
