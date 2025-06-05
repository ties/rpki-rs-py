from datetime import datetime
from typing import Sequence


class FileAndHash:
    """
    Represents a file in a RPKI manifest.
    """
    file: str
    """The file name."""
    
    hash: bytes
    """The file hash."""

class Manifest(Sequence[FileAndHash]):
    """
    Represents a RPKI manifest.
    """
    ski: bytes
    """Subject key identifier."""

    aki: bytes
    """Authority key identifier."""
    
    signing_time: datetime | None
    """The signing time of the manifest."""
    
    this_update: datetime
    """The time of this manifest update."""
    
    next_update: datetime
    """The time of the next manifest update."""
    
    aia: str | None
    """Authority Information Access URI."""
    
    sia: str | None
    """Subject Information Access URI."""
    
    manifest_number: int
    """The manifest number."""
    
    file_list: list[FileAndHash]
    """List of files and their hashes included in the manifest."""
    
    @staticmethod
    def from_content(content: bytes) -> Manifest | None:
        """
        Create a Manifest from raw content bytes.
        
        Args:
            content: The raw manifest content.
            
        Returns:
            An Manifest instance or None if parsing fails.
        """
        ...

def cms_signing_time(content: bytes) -> int | None:
    """
    Extract the signing time from a CMS signed object.
    
    Args:
        content: The raw CMS content.
        
    Returns:
        The signing time as a Unix timestamp (seconds since epoch) or None if not present.
    """
    ...
