import sys

SPACE = ' '
class Column(object):
  ALIGN_LEFT = 1
  ALIGN_RIGHT = 2
  def __init__(self, max_length=sys.maxint, align=ALIGN_LEFT,
               always_first_line=False):
    self.max_length = max_length
    self.alignment = align
    self._always_first_line = always_first_line

  @property
  def message(self):
    """Text to be printed serially with all other Columns"""
    return self._message
    
  @message.setter
  def message(self, new_value):
    self._message = new_value
    self._message_index = 0

  def get_line(self):
    if self._always_first_line:
      self._message_index = 0

    left_to_print = len(self.message) - self._message_index
    length_to_print = min(self.max_length, left_to_print)
    result = ''
    result += self._get_n_chars_and_inc_index(length_to_print)

    # trim and extend `result` if it begins with whitespace
    initial_result_len = len(result)
    result = result.lstrip()
    delta_len = initial_result_len - len(result)
    if delta_len > 0:
      result += self._get_n_chars_and_inc_index(delta_len)

    str_or_unicode = type(result)
    
    if self.alignment is self.ALIGN_LEFT:
      align_func = str_or_unicode.ljust
    elif self.alignment is self.ALIGN_RIGHT:
      align_func = str_or_unicode.rjust

    return align_func(result, self.max_length)

  def _get_n_chars_and_inc_index(self, num_chars):
    return_val = self.message[self._message_index: \
                              self._message_index + num_chars]
    self._message_index += num_chars
    return return_val

  def is_done(self):
    return len(self.message) <= self._message_index
