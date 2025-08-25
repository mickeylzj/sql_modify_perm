from integrated_permission_controller import RefactoredPermissionController
from loguru import logger

class TestRunner:
    def __init__(self, config_path: str = "config.yaml"):
        self.controller = RefactoredPermissionController(config_path)
    
    def run_schema_extraction_tests(self):
        """测试schema提取功能 - 修正版"""
        test_cases = [
            "SELECT * FROM employee",
            "SELECT * FROM data_permission_system.employee",  # 使用实际存在的数据库名
            "SELECT * FROM employee e JOIN salary s ON e.user_id = s.user_id",
            "SELECT e.user_name, s.salary FROM employee e LEFT JOIN salary s ON e.user_id = s.user_id"
        ]
        
        for sql in test_cases:
            logger.info(f"\n=== 测试SQL: {sql} ===")
            table_info = self.controller.extract_table_info_with_schema(sql)
            logger.info(f"提取结果: {table_info}")
    
    def run_basic_tests(self):
        """运行基本测试"""
        test_cases = [
            {
                'description': '简单查询',
                'sql': 'SELECT user_id, user_name FROM employee LIMIT 5',
                'user_id': 1
            },
            {
                'description': '带数据库名的查询',
                'sql': 'SELECT * FROM data_permission_system.employee LIMIT 3',
                'user_id': 2
            }
        ]
        
        for case in test_cases:
            logger.info(f"\n=== 测试案例: {case['description']} ===")
            result = self.controller.execute_query_with_permissions(case['sql'], case['user_id'])
            logger.info(f"执行结果: {result['status']}")
            
            if result['status'] == 'success':
                logger.info(f"查询数据: {len(result['result'])} 条记录")
            else:
                logger.info(f"错误信息: {result['error_message']}")

if __name__ == "__main__":
    test_runner = TestRunner()
    test_runner.run_schema_extraction_tests()
    test_runner.run_basic_tests()
