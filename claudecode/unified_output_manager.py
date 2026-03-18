"""Unified file output manager for security analysis artifacts."""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from claudecode.logger import get_logger

logger = get_logger(__name__)


class UnifiedOutputManager:
    """统一的文件输出管理器，简化实现"""
    
    def __init__(self, session_id: str, base_output_dir: Optional[Path] = None):
        """初始化输出管理器
        
        Args:
            session_id: 会话ID
            base_output_dir: 基础输出目录，如果为None则使用临时目录
        """
        self.session_id = session_id
        
        # 设置基础输出目录
        if base_output_dir:
            self.base_output_dir = Path(base_output_dir)
            self.base_output_dir.mkdir(parents=True, exist_ok=True)
        else:
            import tempfile
            self.base_output_dir = Path(tempfile.gettempdir()) / "security_analysis_artifacts"
            self.base_output_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建会话目录：session_{session_id}/
        self.session_dir = self.base_output_dir / f"session_{session_id}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"统一输出管理器初始化成功：会话目录 {self.session_dir}")
    
    def save_json(self, filename: str, data: Dict[str, Any], sub_dir: Optional[str] = None) -> Path:
        """保存JSON文件
        
        Args:
            filename: 文件名
            data: JSON数据
            sub_dir: 可选的子目录
            
        Returns:
            保存的文件路径
        """
        try:
            if sub_dir:
                dir_path = self.session_dir / sub_dir
                dir_path.mkdir(parents=True, exist_ok=True)
            else:
                dir_path = self.session_dir
            
            file_path = dir_path / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"JSON文件已保存: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"保存JSON文件 {filename} 失败: {str(e)}")
            raise
    
    def save_text(self, filename: str, content: str, sub_dir: Optional[str] = None) -> Path:
        """保存文本文件
        
        Args:
            filename: 文件名
            content: 文件内容
            sub_dir: 可选的子目录
            
        Returns:
            保存的文件路径
        """
        try:
            if sub_dir:
                dir_path = self.session_dir / sub_dir
                dir_path.mkdir(parents=True, exist_ok=True)
            else:
                dir_path = self.session_dir
            
            file_path = dir_path / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.debug(f"文本文件已保存: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"保存文本文件 {filename} 失败: {str(e)}")
            raise
    
    def save_summary(self, summary_data: Dict[str, Any]) -> Path:
        """保存最终摘要文件
        
        Args:
            summary_data: 摘要数据
            
        Returns:
            保存的文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"final_summary_{timestamp}.json"
        
        # 添加会话信息到摘要
        summary_with_metadata = {
            "session_id": self.session_id,
            "session_dir": str(self.session_dir),
            "saved_at": datetime.now().isoformat(),
            "summary": summary_data
        }
        
        return self.save_json(filename, summary_with_metadata)
    
    def get_session_dir(self) -> Path:
        """获取会话目录路径
        
        Returns:
            会话目录路径
        """
        return self.session_dir
    
    def list_artifacts(self) -> List[Path]:
        """列出生成的所有文件
        
        Returns:
            文件路径列表
        """
        if not self.session_dir.exists():
            return []
        
        return list(self.session_dir.rglob("*"))
    
    def cleanup(self) -> bool:
        """清理会话目录
        
        Returns:
            是否清理成功
        """
        try:
            if self.session_dir.exists():
                import shutil
                shutil.rmtree(self.session_dir)
                logger.info(f"已清理会话目录: {self.session_dir}")
                return True
            return False
        except Exception as e:
            logger.error(f"清理会话目录失败: {str(e)}")
            return False