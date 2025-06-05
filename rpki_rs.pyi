from datetime import datetime
from typing import List, Optional


class FileAndHash:
    """
    Represents a file in a RPKI manifest.
    """
    file: str
    """The file name."""
    
    hash: bytes
    """The file hash."""

class Manifest:
    """
    Represents a RPKI manifest.
    """
    ski: bytes
    """Subject key identifier."""
    
    signing_time: Optional[datetime]
    """The signing time of the manifest."""
    
    this_update: datetime
    """The time of this manifest update."""
    
    next_update: datetime
    """The time of the next manifest update."""
    
    aia: Optional[str]
    """Authority Information Access URI."""
    
    sia: Optional[str]
    """Subject Information Access URI."""
    
    manifest_number: int
    """The manifest number."""
    
    file_list: List[FileAndHash]
    """List of files and their hashes included in the manifest."""
    
    # Alias for file_list for backward compatibility based on test usage
    @property
    def file_list(self) -> List[FileAndHash]:
        pass
    
    @staticmethod
    def from_content(content: bytes) -> Optional['RpkiManifest']:
        """
        Create a RpkiManifest from raw content bytes.
        
        Args:
            content: The raw manifest content.
            
        Returns:
            An RpkiManifest instance or None if parsing fails.
        """
        pass

def cms_signing_time(content: bytes) -> Optional[int]:
    """
    Extract the signing time from a CMS signed object.
    
    Args:
        content: The raw CMS content.
        
    Returns:
        The signing time as a Unix timestamp (seconds since epoch) or None if not present.
    """
    pass