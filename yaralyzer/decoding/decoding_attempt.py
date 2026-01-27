"""
Class to manage attempting to decode a chunk of bytes into strings with a given encoding.
"""
from dataclasses import dataclass, field
from sys import byteorder
from typing import Optional

from rich.markup import escape
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch  # Formerly caused circular import issues
from yaralyzer.encoding_detection.character_encodings import (ENCODINGS_TO_ATTEMPT, SINGLE_BYTE_ENCODINGS,
     UTF_8, encoding_width, is_wide_utf)
from yaralyzer.output.theme import ERROR_STYLE, BYTES_BRIGHTER, BYTES_DECODED, BYTES_NO_DIM, GREY_ADDRESS
from yaralyzer.util.helpers.bytes_helper import clean_byte_string, truncate_for_encoding
from yaralyzer.util.helpers.rich_helper import prefix_with_style, unprintable_byte_to_text
from yaralyzer.util.logging import log


@dataclass
class DecodingAttempt:
    """
    Manages the process of attempting to decode a chunk of bytes into a string using a specified encoding.

    This class tries to decode the bytes using the provided encoding, handling both standard and custom decoding
    strategies (including multi-byte encodings and forced decoding attempts). It tracks the outcome, highlights
    the decoded output, and provides information about the decoding process.

    Attributes:
        bytes (bytes): The bytes (including context) to decode.
        bytes_match (BytesMatch): The `BytesMatch` object containing match and context info.
        encoding (str): The encoding to attempt.
        encoding_label (str): Label for the encoding (may include offset info).
        start_offset (int): Byte offset used for decoding (for multi-byte encodings).
        start_offset_label (Optional[str]): String label for the offset, if used.
        was_force_decoded (bool): True if a forced decode was attempted.
        failed_to_decode (bool): True if decoding failed.
        decoded_string (Text): The decoded string as a Rich `Text` object (with highlighting).
    """
    bytes_match: BytesMatch
    encoding: str
    # Non-args
    encoding_label: str = field(init=False)
    failed_to_decode: bool = False
    start_offset: int = 0
    start_offset_label: str | None = None
    was_force_decoded: bool = False

    @property
    def bytes(self) -> bytes:
        return self.bytes_match.surrounding_bytes

    def __post_init__(self):
        # Inferred / derived values
        self.encoding_label = self.encoding
        self.start_offset = 0  # Offset in bytes to start decoding from
        self.start_offset_label = None  # String to indicate what offset we were able to decode
        self.was_force_decoded = False
        self.failed_to_decode = False
        self.decoded_string = self._decode_bytes()

    def _decode_bytes(self) -> Text:
        """
        Tries builtin decode, hands off to other methods for harsher treatment (byte shifting for
        UTF-16/32 and custom decode for the rest) if that fails. Has side effect of setting
        `self.decoded_string` value.
        """
        try:
            decoded_string = self._to_rich_text(escape(self.bytes.decode(self.encoding)))
            log.info(f"{self.encoding} auto-decoded {self.bytes_match}")
            return decoded_string
        except UnicodeDecodeError:
            log.info(f"{self.encoding} failed on 1st pass decoding {self.bytes_match} capture; custom decoding...")
        except LookupError as e:
            log.warning(f"Unknown encoding: {self.encoding}. {e}")
            return self._failed_to_decode_msg_txt(e)

        self.was_force_decoded = True

        if is_wide_utf(self.encoding):
            return self._decode_utf_multibyte()
        else:
            return self._custom_utf_decode()

    def _custom_utf_decode(self) -> Text:
        """
        Returns a `Text` obj representing an attempt to force a UTF-8 encoding onto an array of bytes.
        """
        log.info(f"Custom decoding {self.bytes_match} with {self.encoding}...")
        unprintable_char_map = ENCODINGS_TO_ATTEMPT.get(self.encoding)
        output = Text('', style='bytes.decoded')

        # We use this to skip over bytes consumed by multi-byte UTF-n chars
        skip_next = 0

        for i, b in enumerate(self.bytes):
            if skip_next > 0:
                skip_next -= 1
                continue

            _byte = b.to_bytes(1, byteorder)

            # Color the before and after bytes grey
            if i < self.bytes_match.highlight_start_idx or i > self.bytes_match.highlight_end_idx:
                style = GREY_ADDRESS
            else:
                style = self.bytes_match.highlight_style

            if style not in [GREY_ADDRESS, ERROR_STYLE]:
                if b <= 126:
                    style = BYTES_NO_DIM
                elif b <= 192:
                    style = BYTES_BRIGHTER
                else:
                    style = BYTES_DECODED

            try:
                if unprintable_char_map is not None and b in unprintable_char_map:
                    output.append(unprintable_byte_to_text(unprintable_char_map[b], style=style))
                elif b < 127:
                    output.append(_byte.decode(self.encoding), style=style)
                elif self.encoding != UTF_8:
                    output.append(_byte.decode(self.encoding), style=style)
                # At this point we know it's UTF-8, so it must be a continuation byte
                elif b <= 192:
                    # In UTF-8 bytes from 128 to 192 is a continuation byte
                    output.append(unprintable_byte_to_text(f"CHAR{b}", style=style))
                else:
                    if b <= 223:
                        char_width = 2
                    elif b <= 239:
                        char_width = 3
                    else:
                        char_width = 4

                    wide_char = self.bytes[i:i + char_width].decode(self.encoding)
                    output.append(wide_char, style=style)
                    skip_next = char_width - 1  # Won't be set if there's a decoding exception
                    log.info(f"Skipping next {skip_next} bytes because UTF-8 multibyte char '{wide_char}' used them")
            except UnicodeDecodeError:
                output.append(clean_byte_string(_byte), style=style)

        return output

    def _decode_utf_multibyte(self) -> Text:
        """
        UTF-16/32 are fixed width and multibyte and therefore depend on the position of the starting byte
        so we try several offsets until we find one that at least kind of works.

        Returns:
            Text: Rich `Text` object representing the decoded string with highlighting.
        """
        char_width = encoding_width(self.encoding)
        last_exception = None
        decoded_str = None
        bytes_offset = 0

        # Iterate through the possibly byte offsets until we find a valid decoded string (or don't)
        while bytes_offset < char_width:
            try:
                decoded_str = truncate_for_encoding(self.bytes[bytes_offset:], self.encoding).decode(self.encoding)
            except UnicodeDecodeError as e:
                log.info(f"Exception decoding w/offset {bytes_offset} in {self.encoding}: {e}")
                last_exception = e

            # Append the current bytes_offset to the encoding label if we found a valid decoded string
            if decoded_str is not None:
                log.debug(f"Successfully decoded '{self.encoding}' w/offset {bytes_offset}")
                self.start_offset = bytes_offset
                self.start_offset_label = f"offset {self.start_offset} byte" + ('s' if self.start_offset > 1 else '')
                self.encoding_label = f"{self.encoding} ({self.start_offset_label})"
                break

            bytes_offset += 1

        if decoded_str is not None:
            return self._to_rich_text(decoded_str, bytes_offset)
        else:
            return self._failed_to_decode_msg_txt(last_exception)

    def _to_rich_text(self, _string: str, bytes_offset: int = 0) -> Text:
        """
        Convert a decoded string to highlighted `Text` representation.

        Args:
            _string (str): The decoded string to convert.
            bytes_offset (int): The byte offset used during decoding (for multi-byte encodings).
        Returns:
            Text: The rich `Text` representation of the decoded string with appropriate highlighting.
        """
        # Adjust where we start the highlighting given the multibyte nature of the encodings
        log.debug(f"Stepping through {self.encoding} encoded string...")
        txt = Text('', style=self.bytes_match.style_at_position(0))
        current_byte_idx = 0

        # Prevent unprintable chars other than newline. Some of them disfigure the terminal output permanently
        if self.encoding in SINGLE_BYTE_ENCODINGS:
            is_single_byte_encoding = True
            unprintable_chars = ENCODINGS_TO_ATTEMPT[self.encoding]
        else:
            is_single_byte_encoding = False
            unprintable_chars = {}

        for _i, c in enumerate(_string):
            char_bytes = bytes(c, self.encoding)
            char_width = len(char_bytes)
            style = self.bytes_match.style_at_position(current_byte_idx + bytes_offset)

            # 10 is newline in single byte encodings
            if c.isprintable() or (ord(c) == 10 and is_single_byte_encoding):
                txt.append(c, style)
            elif ord(c) == 9 and is_single_byte_encoding:
                txt.append(unprintable_byte_to_text('\\t', style=style))
            elif ord(c) in unprintable_chars:
                txt.append(unprintable_byte_to_text(unprintable_chars[ord(c)], style=style))
            else:
                txt.append(unprintable_byte_to_text(f"CHAR{ord(c)}", style=style))

            current_byte_idx += char_width

        return txt

    def _failed_to_decode_msg_txt(self, exception: Optional[Exception]) -> Text:
        """Set `self.failed_to_decode` flag and return a `Text` object with the error message."""
        self.failed_to_decode = True
        return prefix_with_style(f"(decode failed: {exception})", style='red dim italic')
