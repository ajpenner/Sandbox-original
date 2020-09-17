  /**
   * Represent the call:
   *     buildWrapper {
   *       settings = "dummy.xml"
   *     }
   *
   * @throws Exception
   */
  @Test
  public void configured() throws Exception {
    def script = loadScript('vars/buildWrapper.groovy')
    script.call({
      settings = "dummy.xml"
    })

    printCallStack()
  }
