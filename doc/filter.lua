local text = require('text')

function Header(el)
  -- drop level-1 header
  if el.level == 1 then
    return {}
  else
    -- decrease level of all headers by 1
    el.level = el.level - 1
    -- convert level-1 headers to uppercase
    if el.level == 1 then
      return pandoc.walk_block(el, {
        Str = function(el)
          return pandoc.Str(text.upper(el.text))
      end })
    end
  end
end
