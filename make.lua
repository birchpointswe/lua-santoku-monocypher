local rock = require("santoku.make.rock")

local env = {
  name = "santoku-monocypher",
  version = "2.2.4-1",
  license = "MIT",
  public = true,
  cflags = {
    rock.include("santoku"),
  },
  ldflags = {},
  dependencies = {
    "lua == 5.1",
    "santoku >= 2.0.0, < 3.0.0"
  },
}

env.homepage = "https://github.com/birchpointswe/lua-" .. env.name
env.tarball = env.name .. "-" .. env.version .. ".tar.gz"
env.download = env.homepage .. "/releases/download/" .. env.version .. "/" .. env.tarball

return { env = env }
