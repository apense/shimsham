
type Foo = ref object
  name: string
  yes: int

const
  MyString = "hello"

const
  MyFoo = [Foo(name: MyString)]